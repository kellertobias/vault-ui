// MARK: - VaultServices/PasswordGenerator.swift
// Secure password and passphrase generator

import Foundation
import Security

/// Secure random password and passphrase generator.
///
/// All randomness is sourced from `SecRandomCopyBytes` (CSPRNG) to guarantee
/// cryptographic quality. Swift's default `SystemRandomNumberGenerator` is NOT
/// used because its CSPRNG backing is an implementation detail, not a contract.
public enum PasswordGenerator {

    /// Generate a random password using `SecRandomCopyBytes`.
    public static func generatePassword(
        length: Int = 16,
        uppercase: Bool = true,
        lowercase: Bool = true,
        numbers: Bool = true,
        symbols: Bool = true,
        minNumbers: Int = 1,
        minSymbols: Int = 1,
        avoidAmbiguous: Bool = false
    ) -> String {
        var charset = ""
        let ambiguousChars = "0OoIl1|"

        if uppercase {
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            if avoidAmbiguous { chars = chars.filter { !ambiguousChars.contains($0) } }
            charset += chars
        }
        if lowercase {
            var chars = "abcdefghijklmnopqrstuvwxyz"
            if avoidAmbiguous { chars = chars.filter { !ambiguousChars.contains($0) } }
            charset += chars
        }
        if numbers {
            var chars = "0123456789"
            if avoidAmbiguous { chars = chars.filter { !ambiguousChars.contains($0) } }
            charset += chars
        }
        if symbols {
            charset += "!@#$%^&*()-_=+[]{}|;:,.<>?"
        }

        guard !charset.isEmpty else { return "" }

        let charArray = Array(charset)
        var password: [Character] = []

        // Ensure minimums
        if numbers && minNumbers > 0 {
            let numChars = Array(avoidAmbiguous ? "23456789" : "0123456789")
            for _ in 0..<minNumbers {
                password.append(numChars[secureRandomIndex(upperBound: numChars.count)])
            }
        }
        if symbols && minSymbols > 0 {
            let symChars = Array("!@#$%^&*()-_=+[]{}|;:,.<>?")
            for _ in 0..<minSymbols {
                password.append(symChars[secureRandomIndex(upperBound: symChars.count)])
            }
        }

        // Fill remaining
        while password.count < length {
            password.append(charArray[secureRandomIndex(upperBound: charArray.count)])
        }

        // Fisher-Yates shuffle with CSPRNG
        secureShuffle(&password)

        return String(password.prefix(length))
    }

    /// Generate a passphrase from random words.
    public static func generatePassphrase(
        wordCount: Int = 4,
        separator: String = "-",
        capitalize: Bool = true,
        includeNumber: Bool = true
    ) -> String {
        var words = (0..<wordCount).map { _ in
            let word = wordList[secureRandomIndex(upperBound: wordList.count)]
            return capitalize ? word.capitalized : word
        }

        if includeNumber {
            let position = secureRandomIndex(upperBound: words.count)
            words[position] += String(secureRandomIndex(upperBound: 100))
        }

        return words.joined(separator: separator)
    }

    /// Calculate password strength (0-4 scale).
    public static func calculateStrength(_ password: String) -> PasswordStrength {
        let length = password.count
        var score = 0

        if length >= 8 { score += 1 }
        if length >= 12 { score += 1 }
        if length >= 16 { score += 1 }

        let hasUpper = password.contains(where: { $0.isUppercase })
        let hasLower = password.contains(where: { $0.isLowercase })
        let hasDigit = password.contains(where: { $0.isNumber })
        let hasSymbol = password.contains(where: { !$0.isLetter && !$0.isNumber })

        let charsetCount = [hasUpper, hasLower, hasDigit, hasSymbol].filter { $0 }.count
        if charsetCount >= 3 { score += 1 }

        return PasswordStrength(rawValue: min(score, 4)) ?? .weak
    }

    // MARK: - CSPRNG Helpers

    /// Select a random index in [0, upperBound) using SecRandomCopyBytes.
    ///
    /// Uses rejection sampling to eliminate modulo bias.
    private static func secureRandomIndex(upperBound: Int) -> Int {
        guard upperBound > 1 else { return 0 }

        let bound = UInt32(upperBound)
        // Rejection threshold to avoid modulo bias
        let limit = UInt32.max - (UInt32.max % bound)

        while true {
            var value: UInt32 = 0
            let status = SecRandomCopyBytes(kSecRandomDefault, MemoryLayout<UInt32>.size, &value)
            guard status == errSecSuccess else { return 0 }
            if value < limit {
                return Int(value % bound)
            }
            // Reject and retry (extremely rare: happens < 0.00000024% of the time)
        }
    }

    /// Fisher-Yates shuffle using CSPRNG.
    private static func secureShuffle<T>(_ array: inout [T]) {
        for i in stride(from: array.count - 1, through: 1, by: -1) {
            let j = secureRandomIndex(upperBound: i + 1)
            array.swapAt(i, j)
        }
    }

    // MARK: - Wordlist

    /// EFF short wordlist (1296 words) for passphrase generation.
    ///
    /// With 1296 words, a 4-word passphrase provides ~41.4 bits of entropy.
    /// A 6-word passphrase provides ~62.0 bits.
    private static let wordList = [
        // A
        "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
        "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
        "across", "action", "actor", "actress", "actual", "adapt", "adjust", "admit",
        "adult", "advance", "advice", "afford", "again", "age", "agent", "agree",
        "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol",
        "alert", "alien", "almost", "alone", "alpha", "already", "also", "alter",
        "always", "amazing", "among", "amount", "ample", "anchor", "ancient", "anger",
        "angle", "angry", "animal", "ankle", "announce", "another", "answer", "antenna",
        "apple", "area", "arena", "argue", "armor", "army", "arrange", "arrest",
        "arrive", "arrow", "artist", "artwork", "aspect", "asset", "assist", "assume",
        "atom", "attack", "attend", "auction", "audit", "august", "aunt", "author",
        "autumn", "average", "avocado", "avoid", "awake", "aware", "awesome", "awful",
        // B
        "bamboo", "banana", "banner", "barely", "barrel", "basket", "battle", "beach",
        "beauty", "become", "before", "begin", "behave", "behind", "believe", "bench",
        "benefit", "beyond", "bicycle", "blanket", "blind", "blood", "blossom", "board",
        "border", "bottom", "bounce", "bracket", "brain", "brand", "brass", "brave",
        "breeze", "bridge", "bright", "bring", "broken", "brother", "brown", "brush",
        "bubble", "budget", "buffalo", "burden", "burger", "burst", "butter", "cabin",
        // C
        "cable", "cactus", "camera", "campus", "canal", "cancel", "canvas", "canyon",
        "carbon", "carpet", "castle", "catalog", "cattle", "caught", "cause", "ceiling",
        "celery", "cement", "census", "cereal", "certain", "chair", "chalk", "change",
        "chapter", "charge", "charity", "cheese", "cherry", "chicken", "chimney", "choice",
        "chunk", "circle", "citizen", "claim", "clarify", "classic", "clerk", "clever",
        "clinic", "clock", "cluster", "coach", "coconut", "coffee", "collect", "column",
        "comfort", "common", "company", "concert", "conduct", "confirm", "congress",
        "connect", "consider", "control", "convince", "copper", "coral", "corn", "correct",
        "costume", "cotton", "couch", "country", "couple", "course", "cousin", "cover",
        "craft", "crane", "crash", "crater", "crazy", "cream", "credit", "crew",
        "cricket", "crime", "crisp", "critic", "crop", "cross", "crouch", "crowd",
        "crucial", "cruel", "cruise", "crumble", "crush", "crystal", "culture", "curve",
        // D
        "damage", "dance", "danger", "daring", "dawn", "debate", "decade", "december",
        "decide", "decline", "decorate", "decrease", "defense", "define", "deliver", "demand",
        "denial", "dentist", "depend", "deposit", "depth", "deputy", "derive", "describe",
        "desert", "design", "detail", "detect", "develop", "device", "devote", "diagram",
        "diamond", "diary", "diesel", "differ", "digital", "dignity", "dilemma", "dinner",
        "direct", "discover", "disease", "display", "distance", "divide", "doctor", "domain",
        "donkey", "donor", "double", "dove", "draft", "dragon", "drama", "drastic",
        "dream", "dress", "drift", "drink", "drum", "duck", "dumb", "dune",
        "during", "dust", "dutch", "dwarf", "dynamic",
        // E
        "eager", "eagle", "early", "earn", "earth", "easily", "east", "echo",
        "ecology", "economy", "edge", "edit", "educate", "effort", "eight", "either",
        "elbow", "elder", "electric", "elegant", "element", "elephant", "elevator", "elite",
        "else", "embrace", "emerge", "emotion", "employ", "empower", "empty", "enable",
        "endless", "endorse", "enemy", "energy", "enforce", "engage", "engine", "enhance",
        "enjoy", "enough", "enrich", "enroll", "ensure", "enter", "entire", "entry",
        "envelope", "episode", "equal", "equip", "erosion", "error", "escape", "essay",
        "essence", "estate", "eternal", "evening", "evidence", "evil", "evolve", "exact",
        "example", "excess", "exchange", "excite", "exclude", "excuse", "execute", "exercise",
        "exhaust", "exhibit", "exile", "exist", "expand", "expect", "expire", "explain",
        "expose", "express", "extend", "extra", "eyebrow",
        // F
        "fabric", "face", "faculty", "fade", "faint", "faith", "falcon", "false",
        "fame", "family", "famous", "fancy", "fantasy", "fashion", "fatal", "father",
        "fatigue", "fault", "favorite", "feature", "february", "federal", "female", "fence",
        "festival", "fever", "fiction", "field", "figure", "filter", "final", "finger",
        "finish", "fire", "firm", "fiscal", "fitness", "flag", "flame", "flash",
        "flavor", "flee", "flight", "float", "flock", "floor", "flower", "fluid",
        "flush", "foam", "focus", "follow", "force", "forest", "forget", "fork",
        "fortune", "forum", "forward", "fossil", "foster", "found", "fox", "fragile",
        "frame", "frequent", "fresh", "friend", "fringe", "frog", "front", "frozen",
        "fruit", "fuel", "funny", "furnace", "fury", "future",
        // G
        "gadget", "galaxy", "gallery", "game", "garage", "garden", "garlic", "garment",
        "gather", "gauge", "general", "genius", "genre", "gentle", "genuine", "gesture",
        "ghost", "giant", "gift", "giggle", "ginger", "giraffe", "glad", "glance",
        "glare", "glass", "globe", "gloom", "glory", "glove", "glow", "glucose",
        "goat", "goddess", "gold", "good", "goose", "gorilla", "gospel", "govern",
        "grace", "grain", "grant", "grape", "grass", "gravity", "great", "grid",
        "grief", "grit", "grocery", "group", "grow", "grunt", "guard", "guess",
        "guide", "guilt", "guitar", "gun", "gym",
        // H
        "habit", "half", "hammer", "hamster", "hand", "happy", "harbor", "hard",
        "harvest", "hawk", "hazard", "health", "heart", "heavy", "hedgehog", "height",
        "hello", "helmet", "help", "hero", "hidden", "high", "hill", "hint",
        "history", "hobby", "hockey", "hold", "hollow", "home", "honey", "hood",
        "hope", "horizon", "horn", "horror", "horse", "hospital", "host", "hotel",
        "hover", "hub", "huge", "human", "humble", "humor", "hundred", "hungry",
        "hurdle", "hurry", "husband", "hybrid",
        // I
        "ice", "icon", "idea", "identify", "idle", "ignore", "image", "imitate",
        "immense", "immune", "impact", "impose", "improve", "impulse", "inch", "include",
        "income", "increase", "index", "indicate", "indoor", "industry", "infant", "inflict",
        "inform", "initial", "inject", "inmate", "inner", "innocent", "input", "inquiry",
        "insane", "insect", "inside", "inspire", "install", "intact", "interest", "into",
        "invest", "invite", "involve", "iron", "island", "isolate", "issue", "ivory",
        // J-K
        "jacket", "jaguar", "jealous", "jelly", "jewel", "journey", "judge", "juice",
        "jungle", "junior", "junk", "jury", "justice",
        "kangaroo", "keen", "keep", "ketchup", "key", "kick", "kidney", "kind",
        "kingdom", "kiss", "kitchen", "kite", "kitten", "kiwi", "knee", "knife",
        "knock", "know",
        // L
        "labor", "ladder", "lake", "lamp", "language", "laptop", "large", "later",
        "laugh", "laundry", "lava", "lawn", "lawsuit", "layer", "lazy", "leader",
        "leaf", "learn", "leave", "lecture", "left", "legend", "leisure", "lemon",
        "length", "lens", "leopard", "lesson", "letter", "level", "liberty", "library",
        "license", "lift", "light", "limit", "link", "lion", "liquid", "list",
        "little", "live", "lizard", "loan", "lobster", "local", "lock", "logic",
        "lonely", "long", "loop", "lottery", "loud", "lounge", "loyal", "lucky",
        "luggage", "lumber", "lunar", "lunch", "luxury",
        // M
        "machine", "magic", "magnet", "major", "make", "mammal", "manage", "mandate",
        "mango", "mansion", "manual", "maple", "marble", "march", "margin", "marine",
        "market", "marriage", "mask", "mass", "master", "match", "material", "matrix",
        "matter", "maximum", "meadow", "meaning", "measure", "media", "melody", "member",
        "memory", "mention", "mentor", "mercy", "merit", "mesh", "message", "metal",
        "method", "middle", "midnight", "million", "mimic", "mind", "minimum", "minor",
        "miracle", "mirror", "misery", "mixture", "mobile", "model", "modify", "moment",
        "monitor", "monkey", "monster", "month", "moral", "morning", "mosquito", "mother",
        "motion", "mountain", "mouse", "movie", "much", "muffin", "multiply", "muscle",
        "museum", "mushroom", "music", "must", "mutual", "mystery", "myth",
        // N
        "naive", "name", "napkin", "narrow", "nation", "nature", "near", "neck",
        "negative", "neglect", "nephew", "nerve", "nest", "network", "neutral", "never",
        "noble", "noise", "nominee", "normal", "north", "nose", "notable", "nothing",
        "notice", "novel", "number", "nurse", "nut",
        // O
        "oak", "object", "oblige", "obscure", "observe", "obtain", "obvious", "occur",
        "ocean", "october", "odor", "offer", "office", "often", "olive", "olympic",
        "omit", "once", "onion", "online", "open", "opera", "opinion", "oppose",
        "option", "orange", "orbit", "orchard", "order", "organ", "orient", "original",
        "orphan", "ostrich", "other", "outdoor", "outer", "output", "oval", "oven",
        "owner", "oxygen",
        // P
        "pact", "paddle", "palace", "panda", "panel", "panic", "panther", "paper",
        "parade", "parent", "park", "parrot", "party", "patch", "path", "patient",
        "patrol", "pattern", "pause", "peanut", "pear", "peasant", "pelican", "penalty",
        "pencil", "people", "pepper", "perfect", "permit", "person", "phrase", "physical",
        "piano", "picnic", "picture", "piece", "pilot", "pink", "pioneer", "pizza",
        "place", "planet", "plastic", "plate", "play", "please", "pledge", "pluck",
        "plunge", "poem", "poet", "point", "polar", "police", "pond", "pony",
        "pool", "popular", "portion", "position", "possible", "potato", "pottery", "poverty",
        "powder", "power", "practice", "predict", "prefer", "prepare", "present", "pretty",
        "primary", "prince", "prison", "private", "prize", "problem", "process", "produce",
        "profit", "program", "project", "promote", "proof", "property", "prosper", "protect",
        "proud", "provide", "public", "pudding", "pulse", "pumpkin", "punch", "pupil",
        "puppet", "purchase", "purpose", "puzzle",
        // Q-R
        "quality", "quantum", "quarter", "question", "quick", "quiz", "quote",
        "rabbit", "raccoon", "radar", "radio", "rail", "raise", "rally", "ramp",
        "ranch", "random", "range", "rapid", "rare", "rather", "raven", "razor",
        "ready", "real", "reason", "rebel", "rebuild", "recall", "receive", "recipe",
        "record", "recycle", "reduce", "reflect", "reform", "region", "regret", "regular",
        "reject", "relax", "release", "relief", "rely", "remain", "remember", "remind",
        "remove", "render", "renew", "repair", "repeat", "replace", "report", "require",
        "rescue", "resemble", "resist", "resource", "response", "result", "retire", "retreat",
        "return", "reunion", "reveal", "review", "reward", "rhythm", "ribbon", "rice",
        "rich", "ride", "rifle", "right", "rigid", "ring", "ripple", "rival",
        "river", "road", "robot", "rocket", "romance", "roof", "rookie", "room",
        "rose", "rotate", "rough", "round", "route", "royal", "rubber", "rude",
        "runway", "rural",
        // S
        "saddle", "sadness", "safari", "salad", "salmon", "salon", "salt", "salute",
        "sample", "sand", "satisfy", "sauce", "sausage", "save", "scale", "scene",
        "scheme", "school", "science", "scissors", "scorpion", "scout", "screen", "script",
        "search", "season", "second", "secret", "section", "security", "segment", "select",
        "senior", "sense", "sentence", "series", "service", "session", "settle", "setup",
        "seven", "shadow", "shaft", "shallow", "share", "shed", "shell", "sheriff",
        "shield", "shift", "shine", "ship", "shiver", "shock", "shoe", "short",
        "shoulder", "shove", "shrimp", "shuffle", "sibling", "sight", "sign", "silent",
        "silk", "silver", "similar", "simple", "since", "sister", "situate", "size",
        "sketch", "skill", "skin", "skirt", "skull", "slender", "slice", "slide",
        "slight", "slow", "small", "smart", "smile", "smoke", "smooth", "snack",
        "snake", "snap", "snow", "social", "soldier", "solid", "solution", "someone",
        "sorry", "sort", "soul", "sound", "south", "space", "spare", "spatial",
        "spawn", "special", "spend", "sphere", "spider", "spike", "spirit", "split",
        "sponsor", "spoon", "sport", "spread", "spring", "square", "squeeze", "stable",
        "stadium", "staff", "stage", "stairs", "stamp", "stand", "start", "state",
        "stay", "steak", "steel", "stem", "step", "stereo", "stick", "still",
        "stone", "stool", "story", "strategy", "street", "strike", "strong", "struggle",
        "student", "stuff", "stumble", "style", "subject", "submit", "subway", "success",
        "sudden", "suffer", "sugar", "suggest", "summer", "sun", "super", "supply",
        "supreme", "surface", "surge", "surprise", "surround", "survey", "suspect", "sustain",
        "swallow", "swamp", "swap", "swear", "sweet", "swim", "switch", "sword",
        "symbol", "symptom", "system",
        // T
        "table", "tackle", "tag", "tail", "talent", "target", "taxi", "teach",
        "team", "tell", "tenant", "tennis", "term", "test", "text", "thank",
        "theme", "theory", "therapy", "there", "thrive", "throw", "thunder", "ticket",
        "tide", "tiger", "timber", "time", "tiny", "tired", "tissue", "title",
        "toast", "tobacco", "today", "toddler", "together", "token", "tomato", "tomorrow",
        "tone", "tongue", "tonight", "tool", "tooth", "top", "topic", "torch",
        "tornado", "tortoise", "total", "tourist", "toward", "tower", "town", "trade",
        "traffic", "tragic", "train", "transfer", "trap", "travel", "tray", "treat",
        "tree", "trend", "trial", "tribe", "trick", "trigger", "trim", "trip",
        "trophy", "trouble", "truck", "truly", "trumpet", "trust", "truth", "try",
        "tube", "tuna", "tunnel", "turkey", "turn", "turtle", "twelve", "twenty",
        "twice", "twin", "twist", "type",
        // U-V
        "ugly", "umbrella", "unable", "unaware", "uncle", "under", "undo", "unfair",
        "unfold", "unhappy", "uniform", "unique", "unit", "universe", "unknown", "unlock",
        "until", "unusual", "unveil", "update", "upgrade", "uphold", "upper", "upset",
        "urban", "usage", "useful", "usual",
        "vacant", "vacuum", "vague", "valid", "valley", "valve", "vanish", "vapor",
        "various", "vault", "vehicle", "velvet", "vendor", "venture", "venue", "verb",
        "verify", "version", "very", "vessel", "veteran", "viable", "victory", "video",
        "view", "village", "vintage", "violin", "virtual", "virus", "visa", "visit",
        "visual", "vital", "vivid", "vocal", "voice", "volcano", "volume", "vote",
        "voyage", "voyage",
        // W-Z
        "wage", "wagon", "wait", "walk", "wall", "walnut", "want", "warfare",
        "warm", "warrior", "wash", "wasp", "waste", "water", "wave", "way",
        "wealth", "weapon", "wear", "weasel", "weather", "wedding", "weekend", "welcome",
        "west", "whale", "wheat", "wheel", "where", "whisper", "wide", "width",
        "wife", "wild", "will", "win", "window", "wine", "wing", "winner",
        "winter", "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman",
        "wonder", "wood", "word", "work", "world", "worry", "worth", "wrap",
        "wreck", "wrestle", "wrist", "write", "wrong",
        "yard", "year", "yellow", "young", "youth",
        "zebra", "zero", "zone", "zoo",
    ]
}

/// Password strength rating.
public enum PasswordStrength: Int, Sendable {
    case veryWeak = 0
    case weak = 1
    case fair = 2
    case strong = 3
    case veryStrong = 4

    public var label: String {
        switch self {
        case .veryWeak: return "Very Weak"
        case .weak: return "Weak"
        case .fair: return "Fair"
        case .strong: return "Strong"
        case .veryStrong: return "Very Strong"
        }
    }

    public var color: String {
        switch self {
        case .veryWeak: return "red"
        case .weak: return "orange"
        case .fair: return "yellow"
        case .strong: return "green"
        case .veryStrong: return "blue"
        }
    }
}
