/// Owns every path-separator decision in SMBee.
///
/// `/` and `\\` are protocol delimiters by Unicode scalar value. Comparing them as
/// `Character`s can miss a delimiter when a combining scalar follows it, which can hide
/// component boundaries and dot segments. Keep path parsing and delimiter-preserving
/// replacement here so callers use the same scalar rule.
///
/// The SwiftLint rule that enforces this convention intentionally does not detect
/// delimiters stored in variables, raw strings, Unicode escapes, comparisons hidden in
/// named predicates, reversed comparisons, nested expressions/closures, or equivalent
/// `CharacterSet` and hand-written loop implementations. It can also match code examples
/// in comments or strings. Those forms require review because the rule is regex-based.
enum SMBPathSeparator {
    enum Kind {
        case smb
        case slash
        case backslash
    }

    static func split(
        _ value: String,
        kind: Kind,
        omittingEmptySubsequences: Bool = true
    ) -> [String] {
        let scalars = value.unicodeScalars
        var components: [String] = []
        var componentStart = scalars.startIndex
        var index = scalars.startIndex

        while index < scalars.endIndex {
            if isSeparator(scalars[index], kind: kind) {
                appendComponent(
                    from: componentStart,
                    to: index,
                    in: scalars,
                    omittingEmptySubsequences: omittingEmptySubsequences,
                    to: &components
                )
                scalars.formIndex(after: &index)
                componentStart = index
            } else {
                scalars.formIndex(after: &index)
            }
        }

        appendComponent(
            from: componentStart,
            to: scalars.endIndex,
            in: scalars,
            omittingEmptySubsequences: omittingEmptySubsequences,
            to: &components
        )
        return components
    }

    static func contains(_ value: String, kind: Kind) -> Bool {
        for scalar in value.unicodeScalars where isSeparator(scalar, kind: kind) {
            return true
        }
        return false
    }

    static func trimmingBoundarySeparators(_ value: String, kind: Kind) -> String {
        let scalars = value.unicodeScalars
        var start = scalars.startIndex
        var end = scalars.endIndex

        if hasLeadingSeparators(value, kind: kind, count: 1) {
            while start < end, isSeparator(scalars[start], kind: kind) {
                scalars.formIndex(after: &start)
            }
        }
        if hasTrailingSeparator(value, kind: kind) {
            while start < end {
                let last = scalars.index(before: end)
                guard isSeparator(scalars[last], kind: kind) else { break }
                end = last
            }
        }

        return String(String.UnicodeScalarView(scalars[start..<end]))
    }

    static func hasLeadingSeparators(_ value: String, kind: Kind, count: Int) -> Bool {
        guard count >= 0 else { return false }
        var remaining = count
        for scalar in value.unicodeScalars {
            guard remaining > 0 else { return true }
            guard isSeparator(scalar, kind: kind) else { return false }
            remaining -= 1
        }
        return remaining == 0
    }

    static func hasTrailingSeparator(_ value: String, kind: Kind) -> Bool {
        guard let last = value.unicodeScalars.last else { return false }
        return isSeparator(last, kind: kind)
    }

    static func replacingSeparators(_ value: String, kind: Kind, with replacement: String) -> String {
        var result = String.UnicodeScalarView()
        for scalar in value.unicodeScalars {
            if isSeparator(scalar, kind: kind) {
                result.append(contentsOf: replacement.unicodeScalars)
            } else {
                result.append(scalar)
            }
        }
        return String(result)
    }

    private static func appendComponent(
        from start: String.UnicodeScalarView.Index,
        to end: String.UnicodeScalarView.Index,
        in scalars: String.UnicodeScalarView,
        omittingEmptySubsequences: Bool,
        to components: inout [String]
    ) {
        guard !omittingEmptySubsequences || start != end else { return }
        components.append(String(String.UnicodeScalarView(scalars[start..<end])))
    }

    private static func isSeparator(_ scalar: Unicode.Scalar, kind: Kind) -> Bool {
        switch kind {
        case .smb:
            scalar.value == 0x2F || scalar.value == 0x5C
        case .slash:
            scalar.value == 0x2F
        case .backslash:
            scalar.value == 0x5C
        }
    }
}
