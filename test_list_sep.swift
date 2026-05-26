import SwiftUI
@available(macOS 13.0, *)
struct TestView: View {
    var body: some View {
        List {
            Text("Test").listRowSeparator(.hidden)
        }
    }
}
