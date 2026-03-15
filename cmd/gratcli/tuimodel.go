package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/cooparo/secure-distributed-chat/pkg/identity"
	"github.com/cooparo/secure-distributed-chat/pkg/ipcprotocol"
)

// Focus states
type focusPane int

const (
	focusContacts focusPane = iota
	focusChat
	focusAddPeer
	focusSetAlias
	focusInfo
)

// Style palette
var (
	appTitleStyle        = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Background(lipgloss.Color("62")).Padding(0, 1)
	sentBubbleStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("15")).Background(lipgloss.Color("62")).Padding(0, 1)
	recvBubbleStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("15")).Background(lipgloss.Color("240")).Padding(0, 1)
	timestampStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Italic(true)
	contactNameStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("15"))
	contactSelectedStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Background(lipgloss.Color("62"))
	contactPreviewStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("246"))
	activePaneBorder     = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("62"))
	inactivePaneBorder   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("240"))
	errorStyle           = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)
	statusStyle          = lipgloss.NewStyle().Foreground(lipgloss.Color("246")).Italic(true)
	headerDimStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("246"))
	sectionTitleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("62"))
)

// Messages for bubbletea
type contactsMsg struct {
	addresses []string
}

type chatMessage struct {
	sender    string
	receiver  string
	timestamp time.Time
	content   string
}

type messagesMsg struct {
	messages []chatMessage
}

type sendResultMsg struct {
	success bool
}

type addPeerResultMsg struct {
	success bool
	host    string
	err     error
}

type removePeerResultMsg struct {
	success bool
	address string
	err     error
}

type errMsg struct {
	err error
}

type tickMsg time.Time

// Model
type model struct {
	ourAddress    string
	contacts      []string
	contactIdx    int
	messages      []chatMessage
	input         textinput.Model
	addPeerInput  textinput.Model
	aliasInput    textinput.Model
	viewport      viewport.Model
	focus         focusPane
	prevFocus     focusPane
	showHelp      bool
	width, height int
	err           error
	statusMsg     string
	aliases       map[string]string
	aliasFile     string
}

func newModel(address identity.IdentityAddress) model {
	ti := textinput.New()
	ti.Placeholder = "Type a message..."
	ti.CharLimit = 500

	api := textinput.New()
	api.Placeholder = "Hostname or IP..."
	api.CharLimit = 256

	ali := textinput.New()
	ali.Placeholder = "Nickname..."
	ali.CharLimit = 32

	vp := viewport.New(0, 0)

	aliasFile := ""
	if home, err := os.UserHomeDir(); err == nil {
		dir := filepath.Join(home, ".config", "grat")
		os.MkdirAll(dir, 0700)
		aliasFile = filepath.Join(dir, "aliases.json")
	}

	aliases := make(map[string]string)
	if aliasFile != "" {
		if data, err := os.ReadFile(aliasFile); err == nil {
			json.Unmarshal(data, &aliases)
		}
	}

	return model{
		ourAddress:   address.Base32(),
		input:        ti,
		addPeerInput: api,
		aliasInput:   ali,
		viewport:     vp,
		focus:        focusContacts,
		aliases:      aliases,
		aliasFile:    aliasFile,
	}
}

func (m *model) saveAliases() {
	if m.aliasFile == "" {
		return
	}
	data, err := json.MarshalIndent(m.aliases, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(m.aliasFile, data, 0600)
}

func (m model) displayName(addr string) string {
	if alias, ok := m.aliases[addr]; ok {
		return alias
	}
	return addr
}

func (m model) Init() tea.Cmd {
	return tea.Batch(
		fetchContacts,
		tickCmd(),
	)
}

func tickCmd() tea.Cmd {
	return tea.Tick(1*time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func fetchContacts() tea.Msg {
	conn, err := connect()
	if err != nil {
		return errMsg{err}
	}
	defer conn.Close()

	mainhdr := &ipcprotocol.MainHeader{
		Version:     1,
		CommandType: ipcprotocol.CommandTypeListContacts,
	}

	pkt, err := mainhdr.MarshalBinary()
	if err != nil {
		return errMsg{err}
	}

	if _, err := conn.Write(pkt); err != nil {
		return errMsg{err}
	}

	// Read response
	respHdrByte := make([]byte, ipcprotocol.SizeMainHeader)
	if _, err := io.ReadFull(conn, respHdrByte); err != nil {
		return errMsg{err}
	}

	var respHdr ipcprotocol.MainHeader
	if err := respHdr.UnmarshalBinary(respHdrByte); err != nil {
		return errMsg{err}
	}

	contactsHdrByte := make([]byte, ipcprotocol.SizeListContactsResponseHeader)
	if _, err := io.ReadFull(conn, contactsHdrByte); err != nil {
		return errMsg{err}
	}

	var contactsHdr ipcprotocol.ListContactsResponseHeader
	if err := contactsHdr.UnmarshalBinary(contactsHdrByte); err != nil {
		return errMsg{err}
	}

	addresses := make([]string, 0, contactsHdr.ContactCount)
	for range contactsHdr.ContactCount {
		addrByte := make([]byte, identity.SizeIdentityAddress)
		if _, err := io.ReadFull(conn, addrByte); err != nil {
			return errMsg{err}
		}
		addresses = append(addresses, identity.IdentityAddress(addrByte).Base32())
	}

	return contactsMsg{addresses: addresses}
}

func fetchMessages(peerAddr string) tea.Cmd {
	return func() tea.Msg {
		conn, err := connect()
		if err != nil {
			return errMsg{err}
		}
		defer conn.Close()

		addr, err := identity.IdentityFromBase32(peerAddr)
		if err != nil {
			return errMsg{err}
		}

		mainhdr := &ipcprotocol.MainHeader{
			Version:     1,
			CommandType: ipcprotocol.CommandTypeMessageRequest,
		}

		pkt, err := mainhdr.MarshalBinary()
		if err != nil {
			return errMsg{err}
		}

		msgreqhdr := &ipcprotocol.MessageRequestHeader{Address: addr}
		pkt, err = msgreqhdr.AppendBinary(pkt)
		if err != nil {
			return errMsg{err}
		}

		if _, err := conn.Write(pkt); err != nil {
			return errMsg{err}
		}

		return readMessagesFromConn(conn)
	}
}

func readMessagesFromConn(conn net.Conn) tea.Msg {
	respHdrByte := make([]byte, ipcprotocol.SizeMainHeader)
	if _, err := io.ReadFull(conn, respHdrByte); err != nil {
		return errMsg{err}
	}

	var respHdr ipcprotocol.MainHeader
	if err := respHdr.UnmarshalBinary(respHdrByte); err != nil {
		return errMsg{err}
	}

	msgrespHdrByte := make([]byte, ipcprotocol.SizeMessageResponseHeader)
	if _, err := io.ReadFull(conn, msgrespHdrByte); err != nil {
		return errMsg{err}
	}

	var msgrespHdr ipcprotocol.MessageResponseHeader
	if err := msgrespHdr.UnmarshalBinary(msgrespHdrByte); err != nil {
		return errMsg{err}
	}

	messages := make([]chatMessage, 0, msgrespHdr.MessageCount)
	for range msgrespHdr.MessageCount {
		msghdrByte := make([]byte, ipcprotocol.SizeMessageHeader)
		if _, err := io.ReadFull(conn, msghdrByte); err != nil {
			return errMsg{err}
		}

		var msghdr ipcprotocol.MessageHeader
		if err := msghdr.UnmarshalBinary(msghdrByte); err != nil {
			return errMsg{err}
		}

		msgData := make([]byte, msghdr.MessageLength)
		if _, err := io.ReadFull(conn, msgData); err != nil {
			return errMsg{err}
		}

		messages = append(messages, chatMessage{
			sender:    msghdr.SenderAddress.Base32(),
			receiver:  msghdr.ReceiverAddress.Base32(),
			timestamp: time.Unix(int64(msghdr.Timestamp), 0),
			content:   string(msgData),
		})
	}

	return messagesMsg{messages: messages}
}

func sendMessage(peerAddr string, message string) tea.Cmd {
	return func() tea.Msg {
		conn, err := connect()
		if err != nil {
			return errMsg{err}
		}
		defer conn.Close()

		addr, err := identity.IdentityFromBase32(peerAddr)
		if err != nil {
			return errMsg{err}
		}

		mainhdr := &ipcprotocol.MainHeader{
			Version:     1,
			CommandType: ipcprotocol.CommandTypeSendMessage,
		}

		pkt, err := mainhdr.MarshalBinary()
		if err != nil {
			return errMsg{err}
		}

		msgBytes := []byte(message)
		sendmsg := &ipcprotocol.SendMessage{
			Header: &ipcprotocol.SendMessageHeader{
				PeerAddress:   addr,
				MessageLength: uint16(len(msgBytes)),
			},
			Data: msgBytes,
		}

		pkt, err = sendmsg.AppendBinary(pkt)
		if err != nil {
			return errMsg{err}
		}

		if _, err := conn.Write(pkt); err != nil {
			return errMsg{err}
		}

		// Read ACK/NACK
		ackByte := make([]byte, ipcprotocol.SizeMainHeader)
		if _, err := io.ReadFull(conn, ackByte); err != nil {
			return errMsg{err}
		}

		var ackHdr ipcprotocol.MainHeader
		if err := ackHdr.UnmarshalBinary(ackByte); err != nil {
			return errMsg{err}
		}

		return sendResultMsg{
			success: ackHdr.CommandType == ipcprotocol.CommandTypeSendMessageAck,
		}
	}
}

func addPeerCmd(host string) tea.Cmd {
	return func() tea.Msg {
		conn, err := connect()
		if err != nil {
			return errMsg{err}
		}
		defer conn.Close()

		conn.SetDeadline(time.Now().Add(35 * time.Second))

		mainhdr := &ipcprotocol.MainHeader{
			Version:     1,
			CommandType: ipcprotocol.CommandTypeAddPeer,
		}

		pkt, err := mainhdr.MarshalBinary()
		if err != nil {
			return errMsg{err}
		}

		addpeer := &ipcprotocol.AddPeer{
			Header: &ipcprotocol.AddPeerHeader{
				AddressLength: uint16(len(host)),
			},
			Data: []byte(host),
		}

		pkt, err = addpeer.AppendBinary(pkt)
		if err != nil {
			return errMsg{err}
		}

		if _, err := conn.Write(pkt); err != nil {
			return addPeerResultMsg{success: false, host: host, err: err}
		}

		// Read ACK/NAC
		ackByte := make([]byte, ipcprotocol.SizeMainHeader)
		if _, err := io.ReadFull(conn, ackByte); err != nil {
			return addPeerResultMsg{success: false, host: host, err: err}
		}

		var ackHdr ipcprotocol.MainHeader
		if err := ackHdr.UnmarshalBinary(ackByte); err != nil {
			return addPeerResultMsg{success: false, host: host, err: err}
		}

		return addPeerResultMsg{
			success: ackHdr.CommandType == ipcprotocol.CommandTypeAddPeerAck,
			host:    host,
		}
	}
}

func removePeerCmd(address string) tea.Cmd {
	return func() tea.Msg {
		conn, err := connect()
		if err != nil {
			return errMsg{err}
		}
		defer conn.Close()

		mainhdr := &ipcprotocol.MainHeader{
			Version:     1,
			CommandType: ipcprotocol.CommandTypeRemovePeer,
		}

		pkt, err := mainhdr.MarshalBinary()
		if err != nil {
			return errMsg{err}
		}

		// Reuse AddPeer wire format (length-prefixed address string)
		payload := &ipcprotocol.AddPeer{
			Header: &ipcprotocol.AddPeerHeader{
				AddressLength: uint16(len(address)),
			},
			Data: []byte(address),
		}

		pkt, err = payload.AppendBinary(pkt)
		if err != nil {
			return errMsg{err}
		}

		if _, err := conn.Write(pkt); err != nil {
			return removePeerResultMsg{success: false, address: address, err: err}
		}

		ackByte := make([]byte, ipcprotocol.SizeMainHeader)
		if _, err := io.ReadFull(conn, ackByte); err != nil {
			return removePeerResultMsg{success: false, address: address, err: err}
		}

		var ackHdr ipcprotocol.MainHeader
		if err := ackHdr.UnmarshalBinary(ackByte); err != nil {
			return removePeerResultMsg{success: false, address: address, err: err}
		}

		return removePeerResultMsg{
			success: ackHdr.CommandType == ipcprotocol.CommandTypeRemovePeerAck,
			address: address,
		}
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		// Handle help overlay
		if m.showHelp {
			switch msg.String() {
			case "?", "q", "esc", "enter":
				m.showHelp = false
				m.focus = m.prevFocus
			}
			return m, nil
		}

		// Handle info overlay
		if m.focus == focusInfo {
			switch msg.String() {
			case "i", "q", "esc", "enter":
				m.focus = m.prevFocus
			}
			return m, nil
		}

		// Handle add-peer input mode
		if m.focus == focusAddPeer {
			switch msg.String() {
			case "enter":
				host := m.addPeerInput.Value()
				m.addPeerInput.SetValue("")
				m.addPeerInput.Blur()
				m.focus = focusContacts
				if host != "" {
					m.statusMsg = "Discovering peer " + host + "..."
					return m, addPeerCmd(host)
				}
				return m, nil
			case "esc":
				m.addPeerInput.SetValue("")
				m.addPeerInput.Blur()
				m.focus = focusContacts
				return m, nil
			default:
				var cmd tea.Cmd
				m.addPeerInput, cmd = m.addPeerInput.Update(msg)
				return m, cmd
			}
		}

		// Handle set-alias input mode
		if m.focus == focusSetAlias {
			switch msg.String() {
			case "enter":
				alias := m.aliasInput.Value()
				m.aliasInput.SetValue("")
				m.aliasInput.Blur()
				m.focus = focusContacts
				if m.contactIdx < len(m.contacts) {
					addr := m.contacts[m.contactIdx]
					if alias == "" {
						delete(m.aliases, addr)
					} else {
						m.aliases[addr] = alias
					}
					m.saveAliases()
					m.statusMsg = "Alias updated"
				}
				return m, nil
			case "esc":
				m.aliasInput.SetValue("")
				m.aliasInput.Blur()
				m.focus = focusContacts
				return m, nil
			default:
				var cmd tea.Cmd
				m.aliasInput, cmd = m.aliasInput.Update(msg)
				return m, cmd
			}
		}

		// Handle chat pane: only ctrl+c, tab, enter are special; rest goes to input
		if m.focus == focusChat {
			switch msg.String() {
			case "ctrl+c":
				return m, tea.Quit
			case "tab":
				m.focus = focusContacts
				m.input.Blur()
				return m, nil
			case "enter":
				if m.input.Value() != "" {
					msg := m.input.Value()
					m.input.SetValue("")
					if m.contactIdx < len(m.contacts) {
						peer := m.contacts[m.contactIdx]
						return m, sendMessage(peer, msg)
					}
				}
				return m, nil
			default:
				var cmd tea.Cmd
				m.input, cmd = m.input.Update(msg)
				return m, cmd
			}
		}

		// Contacts pane keybinds
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "q":
			return m, tea.Quit
		case "tab":
			m.focus = focusChat
			m.input.Focus()
			return m, nil
		case "up":
			if m.contactIdx > 0 {
				m.contactIdx--
				return m, m.loadSelectedChat()
			}
		case "down":
			if m.contactIdx < len(m.contacts)-1 {
				m.contactIdx++
				return m, m.loadSelectedChat()
			}
		case "a":
			m.focus = focusAddPeer
			m.addPeerInput.Focus()
			m.statusMsg = ""
			return m, nil
		case "n":
			if m.contactIdx < len(m.contacts) {
				m.focus = focusSetAlias
				addr := m.contacts[m.contactIdx]
				if existing, ok := m.aliases[addr]; ok {
					m.aliasInput.SetValue(existing)
				}
				m.aliasInput.Focus()
				m.statusMsg = ""
				return m, nil
			}
		case "c":
			if err := clipboard.WriteAll(m.ourAddress); err != nil {
				m.statusMsg = "Copy failed: " + err.Error()
			} else {
				m.statusMsg = "Address copied!"
			}
			return m, nil
		case "d":
			if m.contactIdx < len(m.contacts) {
				addr := m.contacts[m.contactIdx]
				m.statusMsg = "Removing peer " + m.displayName(addr) + "..."
				return m, removePeerCmd(addr)
			}
		case "i":
			m.prevFocus = m.focus
			m.focus = focusInfo
			return m, nil
		case "?":
			m.showHelp = true
			m.prevFocus = m.focus
			return m, nil
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.viewport.Width = m.chatWidth()
		m.viewport.Height = m.chatHeight()
		return m, nil

	case contactsMsg:
		filtered := make([]string, 0, len(msg.addresses))
		for _, addr := range msg.addresses {
			if addr != m.ourAddress {
				filtered = append(filtered, addr)
			}
		}
		m.contacts = filtered
		m.err = nil
		if len(m.contacts) > 0 {
			return m, m.loadSelectedChat()
		}
		return m, nil

	case messagesMsg:
		m.messages = msg.messages
		m.updateViewport()
		m.err = nil
		return m, nil

	case sendResultMsg:
		if msg.success {
			m.statusMsg = "Sent!"
		} else {
			m.statusMsg = "Send failed"
		}
		if m.contactIdx < len(m.contacts) {
			return m, fetchMessages(m.contacts[m.contactIdx])
		}
		return m, nil

	case addPeerResultMsg:
		if msg.success {
			m.statusMsg = fmt.Sprintf("Peer %s added!", msg.host)
			return m, fetchContacts
		}
		if msg.err != nil {
			m.statusMsg = fmt.Sprintf("Failed to add peer %s: %s", msg.host, msg.err.Error())
		} else {
			m.statusMsg = fmt.Sprintf("Failed to add peer %s", msg.host)
		}
		return m, nil

	case removePeerResultMsg:
		if msg.success {
			display := m.displayName(msg.address)
			delete(m.aliases, msg.address)
			m.saveAliases()
			m.statusMsg = fmt.Sprintf("Peer %s removed", display)
			if m.contactIdx >= len(m.contacts)-1 && m.contactIdx > 0 {
				m.contactIdx--
			}
			m.messages = nil
			m.updateViewport()
			return m, fetchContacts
		}
		if msg.err != nil {
			m.statusMsg = fmt.Sprintf("Failed to remove peer: %s", msg.err.Error())
		} else {
			m.statusMsg = "Failed to remove peer"
		}
		return m, nil

	case errMsg:
		m.err = msg.err
		return m, nil

	case tickMsg:
		var cmds []tea.Cmd
		cmds = append(cmds, tickCmd())
		if len(m.contacts) > 0 && m.contactIdx < len(m.contacts) {
			cmds = append(cmds, fetchMessages(m.contacts[m.contactIdx]))
		}
		cmds = append(cmds, fetchContacts)
		return m, tea.Batch(cmds...)
	}

	return m, nil
}

func (m *model) loadSelectedChat() tea.Cmd {
	if m.contactIdx < len(m.contacts) {
		return fetchMessages(m.contacts[m.contactIdx])
	}
	return nil
}

// wordWrap breaks a string into lines no wider than width.
func wordWrap(s string, width int) string {
	if width <= 0 {
		return s
	}
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var lines []string
	line := words[0]
	for _, w := range words[1:] {
		if len(line)+1+len(w) > width {
			lines = append(lines, line)
			line = w
		} else {
			line += " " + w
		}
	}
	lines = append(lines, line)
	return strings.Join(lines, "\n")
}

// getLocalIPs returns non-loopback IPv4 addresses as a comma-separated string.
func getLocalIPs() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "unknown"
	}
	var ips []string
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP
		if ip.IsLoopback() || ip.To4() == nil {
			continue
		}
		ips = append(ips, ip.String())
	}
	if len(ips) == 0 {
		return "none"
	}
	return strings.Join(ips, ", ")
}

func (m *model) updateViewport() {
	maxBubbleW := (m.chatWidth() - 4) * 3 / 4
	if maxBubbleW < 20 {
		maxBubbleW = 20
	}
	chatW := m.chatWidth() - 4

	var sb strings.Builder
	for _, msg := range m.messages {
		isSent := msg.sender == m.ourAddress
		ts := timestampStyle.Render(msg.timestamp.Format("15:04"))
		wrapped := wordWrap(msg.content, maxBubbleW-2) // -2 for padding

		if isSent {
			bubble := sentBubbleStyle.Render(wrapped)
			sb.WriteString(bubble + "\n")
			sb.WriteString(ts + "\n")
		} else {
			senderName := contactNameStyle.Bold(true).Render(m.displayName(msg.sender))
			bubble := recvBubbleStyle.Render(wrapped)
			bubbleW := lipgloss.Width(bubble)
			pad := chatW - bubbleW
			if pad < 0 {
				pad = 0
			}
			sb.WriteString(strings.Repeat(" ", pad) + senderName + "\n")
			sb.WriteString(strings.Repeat(" ", pad) + bubble + "\n")
			tsW := lipgloss.Width(ts)
			tsPad := chatW - tsW
			if tsPad < 0 {
				tsPad = 0
			}
			sb.WriteString(strings.Repeat(" ", tsPad) + ts + "\n")
		}
		sb.WriteString("\n")
	}
	m.viewport.SetContent(sb.String())
	m.viewport.GotoBottom()
}

func (m model) contactsWidth() int {
	w := m.width / 4
	if w < 20 {
		w = 20
	}
	if w > 40 {
		w = 40
	}
	return w
}

func (m model) chatWidth() int {
	return m.width - m.contactsWidth() - 3 // borders
}

func (m model) chatHeight() int {
	return m.height - 6 // header + input + borders
}

// renderOverlay centers a box on a blank screen.
func (m model) renderOverlay(box string) string {
	boxLines := strings.Split(box, "\n")
	boxH := len(boxLines)
	boxW := 0
	for _, l := range boxLines {
		if w := lipgloss.Width(l); w > boxW {
			boxW = w
		}
	}

	padTop := (m.height - boxH) / 2
	if padTop < 0 {
		padTop = 0
	}
	padLeft := (m.width - boxW) / 2
	if padLeft < 0 {
		padLeft = 0
	}

	var overlay strings.Builder
	for range padTop {
		overlay.WriteString(strings.Repeat(" ", m.width) + "\n")
	}
	for _, line := range boxLines {
		overlay.WriteString(strings.Repeat(" ", padLeft) + line + "\n")
	}
	return overlay.String()
}

func (m model) View() string {
	if m.width == 0 {
		return "Loading..."
	}

	cw := m.contactsWidth()
	chw := m.chatWidth()

	// Main header bar
	header := appTitleStyle.Render(" GRAT ") + headerDimStyle.Render("  [?] help  [c] copy  [i] info")

	// --- Contacts pane ---
	var contactLines []string
	contactLines = append(contactLines, sectionTitleStyle.Render("Contacts"))
	contactLines = append(contactLines, headerDimStyle.Render(strings.Repeat("─", cw-4)))

	for i, addr := range m.contacts {
		display := m.displayName(addr)
		if len(display) > cw-4 {
			display = display[:cw-4] + ".."
		}
		if i == m.contactIdx {
			row := contactSelectedStyle.Width(cw - 4).Render(display)
			contactLines = append(contactLines, row)
		} else {
			contactLines = append(contactLines, contactNameStyle.Render(" "+display))
		}
	}

	if len(m.contacts) == 0 {
		contactLines = append(contactLines, contactPreviewStyle.Render("  No contacts"))
	}

	// Footer
	helpLine := contactPreviewStyle.Render("[a]dd [d]el [n]ick [?]help")

	// Add-peer input overlay
	if m.focus == focusAddPeer {
		contactLines = append(contactLines, "")
		contactLines = append(contactLines, sectionTitleStyle.Render("Add peer:"))
		m.addPeerInput.Width = cw - 6
		contactLines = append(contactLines, m.addPeerInput.View())
	}

	// Set-alias input overlay
	if m.focus == focusSetAlias {
		contactLines = append(contactLines, "")
		contactLines = append(contactLines, sectionTitleStyle.Render("Set alias:"))
		m.aliasInput.Width = cw - 6
		contactLines = append(contactLines, m.aliasInput.View())
	}

	contactContent := strings.Join(contactLines, "\n")
	contactPaneHeight := m.height - 4
	lines := strings.Count(contactContent, "\n") + 1
	for lines < contactPaneHeight-1 {
		contactContent += "\n"
		lines++
	}
	contactContent += "\n" + helpLine

	contactBorder := inactivePaneBorder
	if m.focus == focusContacts || m.focus == focusAddPeer || m.focus == focusSetAlias {
		contactBorder = activePaneBorder
	}
	contactPane := contactBorder.Width(cw - 2).Height(contactPaneHeight).Render(contactContent)

	// --- Chat pane ---
	// Chat header
	var chatHeader string
	if m.contactIdx < len(m.contacts) {
		peer := m.contacts[m.contactIdx]
		peerDisplay := m.displayName(peer)
		if len(peerDisplay) > chw-10 {
			peerDisplay = peerDisplay[:chw-10] + ".."
		}
		chatHeader = appTitleStyle.Render(" " + peerDisplay + " ")
		if _, hasAlias := m.aliases[peer]; hasAlias {
			truncAddr := peer
			if len(truncAddr) > chw-6 {
				truncAddr = truncAddr[:chw-6] + ".."
			}
			chatHeader += "\n" + headerDimStyle.Render(truncAddr)
		}
	} else {
		chatHeader = headerDimStyle.Render("Select a contact")
	}

	// Messages viewport
	m.viewport.Width = chw - 4
	m.viewport.Height = m.chatHeight()
	chatContent := chatHeader + "\n" +
		headerDimStyle.Render(strings.Repeat("─", chw-4)) + "\n" +
		m.viewport.View()

	// Input
	m.input.Width = chw - 4
	inputContent := m.input.View()

	// Status/error
	statusLine := ""
	if m.err != nil {
		statusLine = errorStyle.Render("Error: " + m.err.Error())
	} else if m.statusMsg != "" {
		statusLine = statusStyle.Render(m.statusMsg)
	}

	chatFull := chatContent + "\n" + inputContent
	if statusLine != "" {
		chatFull += "\n" + statusLine
	}

	chatPaneHeight := m.height - 4
	chatBorder := inactivePaneBorder
	if m.focus == focusChat {
		chatBorder = activePaneBorder
	}
	chatPane := chatBorder.Width(chw - 2).Height(chatPaneHeight).Render(chatFull)

	body := lipgloss.JoinHorizontal(lipgloss.Top, contactPane, chatPane)
	screen := header + "\n" + body

	// Help overlay
	if m.showHelp {
		helpText := strings.Join([]string{
			sectionTitleStyle.Render("Keyboard Shortcuts"),
			headerDimStyle.Render(strings.Repeat("─", 30)),
			"",
			sectionTitleStyle.Render("General"),
			"  ?          Show this help",
			"  i          Show info",
			"  Tab        Switch pane",
			"  Ctrl+C     Quit",
			"",
			sectionTitleStyle.Render("Contacts pane"),
			"  Up/Down    Navigate contacts",
			"  a          Add peer by hostname",
			"  d          Remove selected peer",
			"  n          Set nickname for contact",
			"  c          Copy own address",
			"  q          Quit",
			"",
			sectionTitleStyle.Render("Chat pane"),
			"  Enter      Send message",
			"",
			sectionTitleStyle.Render("Input modes"),
			"  Enter      Confirm",
			"  Esc        Cancel",
			"",
			headerDimStyle.Render("Press q or Esc to close"),
		}, "\n")

		helpW := 36
		helpH := strings.Count(helpText, "\n") + 1
		helpBox := activePaneBorder.
			Width(helpW).
			Height(helpH).
			Render(helpText)

		screen = m.renderOverlay(helpBox)
	}

	// Info overlay
	if m.focus == focusInfo {
		sent, recv := 0, 0
		for _, msg := range m.messages {
			if msg.sender == m.ourAddress {
				sent++
			} else {
				recv++
			}
		}

		infoText := strings.Join([]string{
			sectionTitleStyle.Render("Node Info"),
			headerDimStyle.Render(strings.Repeat("─", 46)),
			"",
			sectionTitleStyle.Render("Identity"),
			"  " + m.ourAddress,
			"",
			sectionTitleStyle.Render("Network"),
			"  LAN IPs: " + getLocalIPs(),
			"  Server port: 1337",
			"",
			sectionTitleStyle.Render("Stats"),
			fmt.Sprintf("  Peers: %d", len(m.contacts)),
			fmt.Sprintf("  Messages: %d  (sent %d / recv %d)", len(m.messages), sent, recv),
			"",
			headerDimStyle.Render("Press q or Esc to close"),
		}, "\n")

		infoW := 50
		infoH := strings.Count(infoText, "\n") + 1
		infoBox := activePaneBorder.
			Width(infoW).
			Height(infoH).
			Render(infoText)

		screen = m.renderOverlay(infoBox)
	}

	return screen
}
