// MARK: - VaultAppUI/PasswordGeneratorView.swift
// Password generator sheet

import SwiftUI
import VaultServices

/// Password and passphrase generator view.
struct PasswordGeneratorView: View {
    @State private var mode: GeneratorMode = .password
    @State private var generatedValue = ""
    @State private var strength: PasswordStrength = .veryWeak
    @State private var copied = false

    // Password options
    @State private var passwordLength: Double = 16
    @State private var includeUppercase = true
    @State private var includeLowercase = true
    @State private var includeNumbers = true
    @State private var includeSymbols = true
    @State private var minNumbers: Double = 1
    @State private var minSymbols: Double = 1
    @State private var avoidAmbiguous = false

    // Passphrase options
    @State private var wordCount: Double = 4
    @State private var separator = "-"
    @State private var capitalize = true
    @State private var includeNumber = true

    @Environment(\.dismiss) private var dismiss

    enum GeneratorMode: String, CaseIterable {
        case password = "Password"
        case passphrase = "Passphrase"
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Text("Password Generator")
                    .font(.title2.bold())
                Spacer()
                Button {
                    dismiss()
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.title2)
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
            }
            .padding(20)

            // Generated value display
            VStack(spacing: 12) {
                Text(generatedValue)
                    .font(.system(size: 18, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(16)
                    .frame(maxWidth: .infinity)
                    .background(
                        RoundedRectangle(cornerRadius: 10)
                            .fill(.background)
                            .shadow(color: .black.opacity(0.08), radius: 4, y: 2)
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: 10)
                            .stroke(strengthColor.opacity(0.5), lineWidth: 1)
                    )

                // Strength indicator
                HStack(spacing: 4) {
                    ForEach(0..<5) { i in
                        RoundedRectangle(cornerRadius: 2)
                            .fill(i <= strength.rawValue ? strengthColor : Color.gray.opacity(0.2))
                            .frame(height: 4)
                    }
                }

                HStack {
                    Text(strength.label)
                        .font(.caption)
                        .foregroundStyle(strengthColor)
                    Spacer()
                    Text("\(generatedValue.count) characters")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.horizontal, 20)

            // Action buttons
            HStack(spacing: 12) {
                Button {
                    regenerate()
                } label: {
                    Label("Regenerate", systemImage: "arrow.clockwise")
                }

                Button {
                    ClipboardService.shared.copy(generatedValue, clearAfter: 0)
                    withAnimation { copied = true }
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                        withAnimation { copied = false }
                    }
                } label: {
                    Label(copied ? "Copied!" : "Copy", systemImage: copied ? "checkmark" : "doc.on.doc")
                }
                .buttonStyle(.borderedProminent)
            }
            .padding(16)

            Divider()

            // Mode picker
            Picker("Type", selection: $mode) {
                ForEach(GeneratorMode.allCases, id: \.self) { mode in
                    Text(mode.rawValue).tag(mode)
                }
            }
            .pickerStyle(.segmented)
            .padding(.horizontal, 20)
            .padding(.top, 16)

            // Options
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    switch mode {
                    case .password:
                        passwordOptions
                    case .passphrase:
                        passphraseOptions
                    }
                }
                .padding(20)
            }
        }
        .onAppear { regenerate() }
        .onChange(of: mode) { _, _ in regenerate() }
    }

    // MARK: - Password Options

    private var passwordOptions: some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text("Length")
                    Spacer()
                    Text("\(Int(passwordLength))")
                        .font(.system(.body, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
                Slider(value: $passwordLength, in: 8...128, step: 1) {
                    Text("Length")
                }
                .onChange(of: passwordLength) { _, _ in regenerate() }
            }

            Toggle("A-Z Uppercase", isOn: $includeUppercase)
                .onChange(of: includeUppercase) { _, _ in regenerate() }
            Toggle("a-z Lowercase", isOn: $includeLowercase)
                .onChange(of: includeLowercase) { _, _ in regenerate() }
            Toggle("0-9 Numbers", isOn: $includeNumbers)
                .onChange(of: includeNumbers) { _, _ in regenerate() }
            Toggle("!@#$ Symbols", isOn: $includeSymbols)
                .onChange(of: includeSymbols) { _, _ in regenerate() }
            Toggle("Avoid Ambiguous", isOn: $avoidAmbiguous)
                .onChange(of: avoidAmbiguous) { _, _ in regenerate() }

            if includeNumbers {
                HStack {
                    Text("Min Numbers")
                    Spacer()
                    Text("\(Int(minNumbers))")
                        .foregroundStyle(.secondary)
                }
                Slider(value: $minNumbers, in: 0...5, step: 1)
                    .onChange(of: minNumbers) { _, _ in regenerate() }
            }
            if includeSymbols {
                HStack {
                    Text("Min Symbols")
                    Spacer()
                    Text("\(Int(minSymbols))")
                        .foregroundStyle(.secondary)
                }
                Slider(value: $minSymbols, in: 0...5, step: 1)
                    .onChange(of: minSymbols) { _, _ in regenerate() }
            }
        }
    }

    // MARK: - Passphrase Options

    private var passphraseOptions: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("Words")
                Spacer()
                Text("\(Int(wordCount))")
                    .font(.system(.body, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
            Slider(value: $wordCount, in: 3...10, step: 1)
                .onChange(of: wordCount) { _, _ in regenerate() }

            HStack {
                Text("Separator")
                Spacer()
                Picker("Separator", selection: $separator) {
                    Text("-").tag("-")
                    Text(".").tag(".")
                    Text("_").tag("_")
                    Text(" ").tag(" ")
                }
                .frame(width: 80)
                .onChange(of: separator) { _, _ in regenerate() }
            }

            Toggle("Capitalize", isOn: $capitalize)
                .onChange(of: capitalize) { _, _ in regenerate() }
            Toggle("Include Number", isOn: $includeNumber)
                .onChange(of: includeNumber) { _, _ in regenerate() }
        }
    }

    // MARK: - Generation

    private func regenerate() {
        switch mode {
        case .password:
            generatedValue = PasswordGenerator.generatePassword(
                length: Int(passwordLength),
                uppercase: includeUppercase,
                lowercase: includeLowercase,
                numbers: includeNumbers,
                symbols: includeSymbols,
                minNumbers: Int(minNumbers),
                minSymbols: Int(minSymbols),
                avoidAmbiguous: avoidAmbiguous
            )
        case .passphrase:
            generatedValue = PasswordGenerator.generatePassphrase(
                wordCount: Int(wordCount),
                separator: separator,
                capitalize: capitalize,
                includeNumber: includeNumber
            )
        }
        strength = PasswordGenerator.calculateStrength(generatedValue)
    }

    private var strengthColor: Color {
        switch strength {
        case .veryWeak: return .red
        case .weak: return .orange
        case .fair: return .yellow
        case .strong: return .green
        case .veryStrong: return .blue
        }
    }
}
