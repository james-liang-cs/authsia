import Foundation
import Darwin

struct CheckboxTUI {

    static let defaultPageSize = 50

    struct CheckboxItem: Identifiable {
        let id = UUID()
        let secret: DetectedSecret
        var isSelected: Bool
        var isFocused: Bool
    }

    struct SelectionState {
        var items: [CheckboxItem]
        private(set) var currentIndex: Int
        let pageSize: Int

        init(secrets: [DetectedSecret], pageSize: Int = CheckboxTUI.defaultPageSize) {
            self.items = secrets.map { CheckboxItem(secret: $0, isSelected: false, isFocused: false) }
            self.currentIndex = 0
            self.pageSize = max(1, pageSize)
            if !items.isEmpty {
                items[0].isFocused = true
            }
        }

        var pageCount: Int {
            max(1, (items.count + pageSize - 1) / pageSize)
        }

        var currentPage: Int {
            guard !items.isEmpty else { return 0 }
            return currentIndex / pageSize
        }

        var pageRange: Range<Int> {
            guard !items.isEmpty else { return 0..<0 }
            let start = currentPage * pageSize
            return start..<min(start + pageSize, items.count)
        }

        var visibleItems: [CheckboxItem] {
            Array(items[pageRange])
        }

        var selectedSecrets: [DetectedSecret] {
            items.filter(\.isSelected).map(\.secret)
        }

        mutating func moveUp() {
            guard currentIndex > 0 else { return }
            focus(index: currentIndex - 1)
        }

        mutating func moveDown() {
            guard currentIndex < items.count - 1 else { return }
            focus(index: currentIndex + 1)
        }

        mutating func previousPage() {
            guard currentPage > 0 else { return }
            focus(index: max(0, (currentPage - 1) * pageSize))
        }

        mutating func nextPage() {
            guard currentPage < pageCount - 1 else { return }
            focus(index: min(items.count - 1, (currentPage + 1) * pageSize))
        }

        mutating func toggleFocusedSelection() {
            guard items.indices.contains(currentIndex) else { return }
            items[currentIndex].isSelected.toggle()
        }

        mutating func toggleCurrentPageSelection() {
            let range = pageRange
            guard !range.isEmpty else { return }
            let shouldSelect = !range.allSatisfy { items[$0].isSelected }
            for index in range {
                items[index].isSelected = shouldSelect
            }
        }

        mutating func toggleAllPagesSelection() {
            let shouldSelect = !items.allSatisfy(\.isSelected)
            for index in items.indices {
                items[index].isSelected = shouldSelect
            }
        }

        mutating func clearSelection() {
            for index in items.indices {
                items[index].isSelected = false
            }
        }

        private mutating func focus(index: Int) {
            guard items.indices.contains(index) else { return }
            if items.indices.contains(currentIndex) {
                items[currentIndex].isFocused = false
            }
            currentIndex = index
            items[currentIndex].isFocused = true
        }
    }

    /// Truncates a file path intelligently, preserving the most meaningful segment.
    /// Priority: home-relative (~/) → parent/filename → truncated filename.
    static func smartTruncatePath(_ path: String, maxLength: Int) -> String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        // Replace home prefix with ~
        let normalized = path.hasPrefix(home)
            ? "~" + String(path.dropFirst(home.count))
            : path

        if normalized.count <= maxLength {
            return normalized
        }

        // Try parent/filename (e.g. "myapp/.env.production")
        let url = URL(fileURLWithPath: normalized)
        let filename = url.lastPathComponent
        guard !filename.isEmpty else {
            return String(normalized.prefix(maxLength))
        }
        let parent = url.deletingLastPathComponent().lastPathComponent
        let parentFile = "\(parent)/\(filename)"

        if parentFile.count <= maxLength {
            return parentFile
        }

        // Last resort: truncate filename itself
        return String(filename.prefix(maxLength))
    }

    static func selectSecrets(_ secrets: [DetectedSecret]) -> [DetectedSecret] {
        var state = SelectionState(secrets: secrets)
        guard !state.items.isEmpty else { return [] }
        
        // Enable raw mode for proper key capture
        let originalTermios = enableRawMode()
        defer {
            disableRawMode(originalTermios)
            print("\u{001B}[?25h", terminator: "")
        }
        
        print("\u{001B}[?25l", terminator: "")
        
        render(state: state)
        
        while true {
            guard let key = readKey() else { continue }
            
            switch key {
            case .up:
                state.moveUp()
                render(state: state)
                
            case .down:
                state.moveDown()
                render(state: state)

            case .previousPage:
                state.previousPage()
                render(state: state)

            case .nextPage:
                state.nextPage()
                render(state: state)
                
            case .space:
                state.toggleFocusedSelection()
                render(state: state)

            case .page:
                state.toggleCurrentPageSelection()
                render(state: state)
                
            case .all:
                state.toggleAllPagesSelection()
                render(state: state)
                
            case .none:
                state.clearSelection()
                render(state: state)
                
            case .enter:
                clearScreen()
                return state.selectedSecrets
                
            case .escape, .quit:
                clearScreen()
                return []
            }
        }
    }
    
    private static func enableRawMode() -> termios {
        var raw = termios()
        tcgetattr(STDIN_FILENO, &raw)
        let original = raw
        
        // Disable canonical mode and echo
        raw.c_lflag &= ~(UInt(ECHO | ICANON | ISIG | IEXTEN))
        raw.c_iflag &= ~(UInt(ICRNL | IXON | INPCK | ISTRIP))
        raw.c_cflag &= ~(UInt(CSIZE | PARENB))
        raw.c_cflag |= UInt(CS8)
        raw.c_cc.0 = 0  // VMIN - return immediately
        raw.c_cc.1 = 1  // VTIME - minimum characters
        
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw)
        
        return original
    }
    
    private static func disableRawMode(_ original: termios) {
        var term = original
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &term)
    }
    
    private static func render(state: SelectionState) {
        clearScreen()
        
        print("")
        print("╔════════════════════════════════════════════════════════════════╗")
        print("║          SELECT SECRETS TO MIGRATE TO AUTHSIA                  ║")
        print("╚════════════════════════════════════════════════════════════════╝")
        print("")
        print("Use ↑↓ to navigate, ←→ to page, SPACE to toggle, ENTER to confirm")
        print("Press 'p' to select page, 'a' to select all pages, 'n' to select none, 'q' to quit")
        print("Page \(state.currentPage + 1)/\(state.pageCount)  Showing \(state.pageRange.lowerBound + 1)-\(state.pageRange.upperBound) of \(state.items.count)")
        print("")
        print("┌─────┬──────────────────┬───────────┬────────────────┬──────────────────────────────┐")
        print("│ [✓] │ Confidence       │ Type      │ File           │ Key                          │")
        print("├─────┼──────────────────┼───────────┼────────────────┼──────────────────────────────┤")
        
        for item in state.visibleItems {
            let checkbox = item.isSelected ? "[✓]" : "[ ]"
            let focusIndicator = item.isFocused ? ">" : " "
            let confidence = "\(item.secret.confidence.displayIcon) \(item.secret.confidence.rawValue.uppercased())"
            let type = String(item.secret.type.description.prefix(9)).padding(toLength: 9, withPad: " ", startingAt: 0)
            let fileName = CheckboxTUI.smartTruncatePath(item.secret.filePath, maxLength: 14)
                .padding(toLength: 14, withPad: " ", startingAt: 0)
            let key = String(item.secret.key.prefix(28)).padding(toLength: 28, withPad: " ", startingAt: 0)
            
            let line = "│ \(focusIndicator)\(checkbox) │ \(confidence.padding(toLength: 16, withPad: " ", startingAt: 0)) │ \(type) │ \(fileName) │ \(key) │"
            
            if item.isFocused {
                print("\u{001B}[7m" + line + "\u{001B}[0m")
            } else {
                print(line)
            }
        }
        
        print("└─────┴──────────────────┴───────────┴────────────────┴──────────────────────────────┘")
        print("")
        print("Selected: \(state.items.filter { $0.isSelected }.count)/\(state.items.count)")
    }
    
    private static func clearScreen() {
        print("\u{001B}[2J\u{001B}[H", terminator: "")
    }
    
    private enum Key {
        case up, down, previousPage, nextPage, space, enter, escape, quit, page, all, none
    }
    
    private static func readKey() -> Key? {
        var buffer = [UInt8](repeating: 0, count: 4)
        let readCount = read(STDIN_FILENO, &buffer, 4)
        
        guard readCount > 0 else { return nil }
        
        if buffer[0] == 27 && readCount >= 3 {
            if buffer[1] == 91 {
                switch buffer[2] {
                case 65: return .up
                case 66: return .down
                case 67: return .nextPage
                case 68: return .previousPage
                default: return nil
                }
            }
            return .escape
        }
        
        switch buffer[0] {
        case 32: return .space
        case 10, 13: return .enter
        case 113, 81: return .quit
        case 112, 80: return .page
        case 97, 65: return .all
        case 110, 78: return Key.none
        case 27: return .escape
        default: return nil
        }
    }
}
