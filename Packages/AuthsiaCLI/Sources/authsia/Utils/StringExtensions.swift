import Foundation

extension String {
    func padding(toLength length: Int, withPad padString: String, startingAt padIndex: Int) -> String {
        if self.count >= length {
            return String(self.prefix(length))
        }
        let padding = String(repeating: padString, count: length - self.count)
        return self + padding
    }
}
