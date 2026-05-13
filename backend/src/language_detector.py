"""
Language Detection Module
Detects programming language from code content using heuristics and syntax patterns.
"""

import re
from typing import Optional, Tuple

# Language signatures - ordered by specificity (most specific first)
LANGUAGE_SIGNATURES = {
    'rust': [
        (r'\bfn\s+\w+\s*\(', 15),
        (r'\blet\s+mut\s+', 20),
        (r'\blet\s+\w+\s*:', 10),
        (r'\bimpl\s+\w+', 15),
        (r'\bpub\s+fn\s+', 15),
        (r'\buse\s+std::', 20),
        (r'\buse\s+\w+::', 10),
        (r'->\s*(Result|Option|Self|String|Vec|Box|Arc|Rc|bool|i8|i16|i32|i64|i128|u8|u16|u32|u64|u128|f32|f64|usize|isize)\b', 15),
        (r'\bmatch\s+\w+', 12),
        (r'\bmod\s+\w+', 10),
        (r'\bstruct\s+\w+', 10),
        (r'\benum\s+\w+\s*{', 8),
        (r'\bprintln!\s*\(', 20),
        (r'\bvec!\s*\[', 15),
        (r'#\[derive\(', 15),
        (r'&\s*mut\s+', 10),
        (r'&str\b', 15),                         # borrowed string slice — Rust-exclusive (\b before & invalid)
        (r'\bstd::(?:io|fmt|sync|collections|error|net|path|fs)\b', 18),  # Rust std modules
        (r'\bSome\(', 8),
        (r'\bNone\b', 5),
        (r'\bunwrap\(\)', 10),
        (r'\bOption<', 10),
        (r'\bBox<', 8),
        (r'\bArc<', 8),
    ],
    'kotlin': [
        (r'\bfun\s+\w+\s*\(', 15),
        (r'\bval\s+\w+', 12),
        (r'\bvar\s+\w+\s*:', 10),
        (r'\bdata\s+class\s+', 20),
        (r'\bcompanion\s+object', 20),
        (r'\bsuspend\s+fun', 20),
        (r'\bobject\s+\w+\s*:', 12),
        (r'\bwhen\s*\(', 10),
        (r'\bsealed\s+class', 15),
        (r'\binit\s*{', 10),
        (r'\?\s*\.', 8),
        (r'\?:', 5),
        (r'\bprintln\s*\(', 8),
        (r'\bimport\s+kotlin\.', 15),
        (r'\bimport\s+android\.', 15),
    ],
    'swift': [
        (r'\bimport\s+Foundation', 25),
        (r'\bimport\s+UIKit', 25),
        (r'\bimport\s+SwiftUI', 25),
        (r'\bvar\s+body\s*:\s*some\s+View', 20),
        (r'@State\s+', 20),
        (r'@Published\s+', 15),
        (r'@ObservedObject', 15),
        (r'\bguard\s+let\s+', 18),              # raised: Swift-exclusive pattern
        (r'\bif\s+let\s+', 12),                 # optional binding — Swift-exclusive
        (r'\btry\?\s+', 18),                    # optional try — Swift-exclusive
        (r'\btry!\s+', 15),                     # forced try — Swift-exclusive
        (r'\bfunc\s+\w+\s*\(', 10),
        (r'\bstruct\s+\w+\s*:', 10),
        (r'\bprotocol\s+\w+', 12),
        (r'\bclass\s+\w+\s*:', 8),
        (r'\blet\s+\w+\s*:', 8),
        (r'\bNSObject\b', 12),
        (r'\bprint\s*\(', 5),
        (r'\benum\s+\w+\s*:', 8),
        (r'\bURL\s*\(string:', 15),             # Swift URL init with named param
        (r'Data\s*\(contentsOf:', 15),          # Swift Data init
        (r'\\\(', 10),                          # string interpolation \(...)
        (r'\bnil\b', 6),
        (r'\bOptional<', 12),
    ],
    'typescript': [
        (r'\binterface\s+\w+\s*{', 25),           # exclusive TS keyword
        (r':\s*(string|number|boolean|any|void|never|unknown|object)\b', 12),
        (r'\btype\s+\w+\s*=', 15),
        (r'\bReadonly<', 15),
        (r'\benum\s+\w+\s*{', 20),                # raised: enum keyword is strong TS signal
        (r'\bconst\s+\w+\s*:\s*[A-Z]\w+', 14),  # typed const with user type — TS-exclusive
        (r'\b\w+\s*:\s*(string|number|boolean|void|never|unknown)\s*[;,)]', 12),
        (r'<T(?:\s+extends\s+\w+)?>', 12),         # generic type param
        (r'\bas\s+\w+\b', 8),                       # type assertion
        (r'\bsatisfies\s+\w+', 10),
        (r'<\w+>\s*\(', 5),
        (r'\basync\s+function', 3),
    ],
    'java': [
        (r'\bpublic\s+(static\s+)?(void|class|interface)', 15),
        (r'\bprivate\s+(static\s+)?(void|class)', 12),
        (r'\bString\s+\w+\s*=', 10),
        (r'\bString\s+\w+\b', 25),              # capital String = Java-exclusive type
        (r'\bString\[\]\s+\w+', 12),            # String[] args
        (r'\bSystem\.out\.print', 15),
        (r'\bimport\s+java\.', 20),
        (r'\bnew\s+\w+\s*\(', 5),
        (r'\bextends\s+\w+', 8),
        (r'\bimplements\s+\w+', 10),
        (r'\.length\(\)', 10),                  # Java/C# .length() call
        (r'for\s*\(\s*int\s+\w+\s*=', 12),     # Java for(int i=0; ...) pattern
        (r'\bInteger\b|\bDouble\b|\bBoolean\b|\bLong\b', 10),  # Java boxed types
        (r'\b(?:public|private|protected)\s+(?:static\s+)?void\s+\w+\s*\(', 12),  # Java access-modified void method
        # JDBC / common Java API patterns
        (r'\bPreparedStatement\b', 20),
        (r'\.prepareStatement\s*\(', 20),
        (r'\.setString\s*\(', 15),
        (r'\.setInt\s*\(', 15),
        (r'\.executeQuery\s*\(', 15),
        (r'\.executeUpdate\s*\(', 15),
        (r'\bResultSet\b', 15),
        (r'\bConnection\s+\w+', 12),
        (r'\bint\s+\w+\s*=\s*\d+', 8),
        (r'\bboolean\s+\w+', 8),
        (r'\bArrayList\b', 10),
        (r'\bHashMap\b', 10),
        (r'@Override', 12),
        (r'\bthrows\s+\w+', 10),
    ],
    'c_sharp': [
        (r'\busing\s+System', 20),
        (r'\bnamespace\s+\w+', 15),
        (r'\bConsole\.(Write|Read)', 15),
        (r'\bvar\s+\w+\s*=', 5),
        (r'\basync\s+Task', 10),
        (r'\bpublic\s+partial\s+class', 12),
    ],
    'cpp': [
        (r'#include\s*<\w+>', 15),              # <iostream>, <vector> — no .h
        (r'\bstd::', 20),
        (r'\bcout\s*<<', 20),                   # raised: C++-exclusive
        (r'\bcin\s*>>', 15),
        (r'\busing\s+namespace\s+std', 25),     # raised: very C++-specific
        (r'\btemplate\s*<', 12),
        (r'\bclass\s+\w+\s*:', 8),
        (r'nullptr', 10),
        (r'\bvector<', 15),                     # STL container
        (r'\bstd::string\b', 15),
        (r'\bstd::vector\b', 15),
        (r'\bint\s+main\s*\(', 15),             # shared with C but boosts C++ score
        (r'\bdelete\s+', 10),
        (r'\bnew\s+\w+\s*\(', 8),
    ],
    'c': [
        (r'#include\s*<stdio\.h>', 20),
        (r'#include\s*<stdlib\.h>', 20),
        (r'#include\s*<string\.h>', 20),
        (r'#include\s*<\w+\.h>', 12),
        (r'\bprintf\s*\(', 15),
        (r'\bscanf\s*\(', 15),
        (r'\bfprintf\s*\(', 12),
        (r'\bsprintf\s*\(', 12),
        (r'\bmalloc\s*\(', 12),
        (r'\bcalloc\s*\(', 12),
        (r'\brealloc\s*\(', 12),
        (r'\bfree\s*\(', 10),
        (r'\bint\s+main\s*\(', 15),
        (r'\bchar\s*\*', 8),
        (r'\bchar\s+\w+\s*\[\d*\]', 12),  # char buffer[8]
        (r'\bstrcpy\s*\(', 14),
        (r'\bstrncpy\s*\(', 14),
        (r'\bstrcat\s*\(', 12),
        (r'\bstrncat\s*\(', 12),
        (r'\bstrcmp\s*\(', 10),
        (r'\bstrlen\s*\(', 10),
        (r'\bgets\s*\(', 12),
        (r'\bfgets\s*\(', 10),
        (r'\bmemcpy\s*\(', 10),
        (r'\bmemset\s*\(', 10),
        (r'\bunsigned\s+(long|int|char|short)\b', 6),   # C unsigned — weak alone; C wins via other patterns
        (r'\bsize_t\b', 10),
        (r'\bvoid\s+\w+\s*\([^)]*\)', 6),  # void func(...) — generic but contributes
        (r'\bint\s+\w+\s*\([^)]*char\s*\*', 8),  # int func(...char*...)
        (r'\bNULL\b', 6),
        (r'\bEOF\b', 6),
        (r'\bFILE\s*\*', 10),
    ],
    'go': [
        (r'\bpackage\s+\w+', 25),               # raised: very Go-specific
        (r'\bfunc\s+\w+\s*\(', 15),
        (r'\bfmt\.(Print|Scan|Sprint|Fprintf)', 18),  # fmt package = Go
        (r':=', 12),                             # short variable declaration
        (r'\bgo\s+func', 15),
        (r'\bchan\s+\w+', 15),
        (r'\bdefer\s+', 12),
        (r'\bimport\s+\(', 12),                 # multi-import block (Go-exclusive)
        (r'\bnil\b', 8),
        (r'\bmake\s*\(', 8),
    ],
    'ruby': [
        (r'\bdef\s+\w+', 8),                    # lowered: shared with Python
        (r'\bend\s*$', 18),                     # raised: Ruby-exclusive block closer
        (r'\bend\b', 8),                         # end mid-line also distinctive
        (r'\brequire\s+[\'"]', 15),
        (r'\battr_(reader|writer|accessor)', 18),
        (r'\bputs\s+', 18),                     # raised: Ruby-exclusive output
        (r'\bclass\s+\w+\s*<', 12),
        (r'\.each\s+do\s*\|', 15),
        (r'\bdo\s*\|', 12),                     # block with pipe — Ruby-exclusive
        (r'#\{', 10),                           # string interpolation #{...}
        (r'\bnil\b', 6),
        (r'\btrue\b|\bfalse\b', 5),             # lowercase booleans (Ruby)
        (r'\b@\w+', 8),                         # instance var @name
        (r'\b@@\w+', 10),                       # class var @@name
    ],
    'php': [
        (r'<\?php', 25),
        (r'\$\w+\s*=', 15),
        (r'\becho\s+', 12),
        (r'\bfunction\s+\w+\s*\(', 8),
        (r'\barray\s*\(', 10),
        (r'\->', 5),
    ],
    'javascript': [
        (r'\bconst\s+\w+\s*=', 4),                 # lowered — shared with TS
        (r'\blet\s+\w+\s*=', 4),                   # lowered — shared with TS
        (r'\bvar\s+\w+\s*=', 3),                   # lowered — shared with TS
        (r'\bfunction\s+\w+\s*\(', 8),
        (r'=>', 4),                                 # lowered — shared with TS
        (r'\bconsole\.(log|error|warn)', 15),
        (r'\brequire\s*\([\'"]', 12),
        (r'\bexport\s+(default|const|function)', 12),
        (r'\bimport\s+.*\s+from\s+[\'"]', 12),
        (r'\bdocument\.', 12),
        (r'\bwindow\.', 10),
    ],
    'python': [
        (r'\bdef\s+\w+\s*\(', 10),
        (r'\bimport\s+\w+', 10),
        (r'\bfrom\s+\w+\s+import', 12),
        (r'\bprint\s*\(', 4),                   # lowered: common across languages
        (r'\bclass\s+\w+\s*(\(|:)', 10),
        (r'\bself\.\w+', 12),
        (r'\bif\s+.*:', 5),
        (r'\belif\s+', 10),
        (r'\b__\w+__', 10),
        (r'\b(True|False|None)\b', 8),          # Python capitalised keywords
        (r'\bis\s+(?:not\s+)?None\b', 10),      # Python identity check — exclusive
        (r'\bfor\s+\w+\s+in\s+', 10),           # Python-style for loop
        (r'\blambda\s+', 10),
        (r'\byield\s+', 10),
        (r'\bwith\s+\w+.*:', 8),                # with statement
        (r'\bpass\b', 8),
        (r'\braise\s+\w+', 8),
        (r'\bexcept\s+\w+', 10),
        (r'(?m)^\s*@\w+(?:\.\w+)*', 12),        # decorator: @decorator or @app.route
        (r'\bjsonify\s*\(', 10),                # Flask/common Python web framework
        (r'\brequest\.\w+\s*\(', 8),            # Flask/Django request object
    ],
}

# Tree-sitter language name mapping
LANGUAGE_MAP = {
    'python': 'python',
    'java': 'java',
    'javascript': 'javascript',
    'typescript': 'typescript',
    'c': 'c',
    'cpp': 'cpp',
    'c_sharp': 'c_sharp',
    'go': 'go',
    'ruby': 'ruby',
    'php': 'php',
    'rust': 'rust',
    'kotlin': 'kotlin',
    'swift': 'swift',
}


def detect_language(code: str, filename: Optional[str] = None) -> Tuple[str, float]:
    """
    Detect the programming language of the given code.
    
    Returns:
        Tuple of (language_name, confidence_score)
        language_name is one of: python, java, javascript, typescript, c, cpp, c_sharp, go, ruby, php
        confidence_score is between 0.0 and 1.0
    """
    # Try filename extension first
    if filename:
        ext_lang = _detect_from_extension(filename)
        if ext_lang:
            return ext_lang, 1.0
    
    # Fall back to content analysis
    scores = {}
    
    for lang, patterns in LANGUAGE_SIGNATURES.items():
        score = 0
        for pattern, weight in patterns:
            matches = len(re.findall(pattern, code, re.MULTILINE))
            score += matches * weight
        scores[lang] = score
    
    if not scores or max(scores.values()) == 0:
        return 'python', 0.0  # Default to Python with zero confidence

    best_lang = max(scores, key=scores.get)
    max_score = scores[best_lang]

    sorted_vals = sorted(scores.values(), reverse=True)
    second_score = sorted_vals[1] if len(sorted_vals) > 1 else 0

    if second_score == 0:
        # Exclusive match: only one language has any signal.
        # 12 pts = a single strong indicator (e.g. strcpy, package main) → ~1.0
        confidence = min(1.0, max_score / 12.0)
    else:
        # Competitive: combine three independent signals.
        #   margin        — how unique the winner is vs runner-up (0=tied, 1=exclusive)
        #   abs_part      — absolute signal strength (saturates at 20 pts)
        #   dominance     — winner/runner-up score ratio (≥3× → full boost)
        margin = (max_score - second_score) / max_score
        abs_part = min(1.0, max_score / 20.0)
        dominance_boost = min(1.0, (max_score / max(second_score, 1)) / 3.0)
        confidence = min(1.0, margin * 0.2 + abs_part * 0.5 + dominance_boost * 0.3)

    return best_lang, confidence


def _detect_from_extension(filename: str) -> Optional[str]:
    """Detect language from file extension."""
    ext_map = {
        '.py': 'python',
        '.java': 'java',
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.ts': 'typescript',
        '.tsx': 'typescript',
        '.c': 'c',
        '.h': 'c',
        '.cpp': 'cpp',
        '.cc': 'cpp',
        '.cxx': 'cpp',
        '.hpp': 'cpp',
        '.cs': 'c_sharp',
        '.go': 'go',
        '.rb': 'ruby',
        '.php': 'php',
        '.rs': 'rust',
        '.kt': 'kotlin',
        '.kts': 'kotlin',
        '.swift': 'swift',
    }
    
    for ext, lang in ext_map.items():
        if filename.lower().endswith(ext):
            return lang
    
    return None


def get_supported_languages() -> list:
    """Return list of supported language names."""
    return list(LANGUAGE_MAP.keys())


if __name__ == "__main__":
    # Test the detector
    test_cases = [
        ("def hello():\n    print('Hello')", "python"),
        ("public class Main { public static void main(String[] args) {} }", "java"),
        ("const x = () => console.log('hi');", "javascript"),
        ("package main\n\nfunc main() { fmt.Println(\"Hi\") }", "go"),
        ("#include <stdio.h>\nint main() { printf(\"hi\"); }", "c"),
    ]
    
    for code, expected in test_cases:
        detected, conf = detect_language(code)
        status = "✓" if detected == expected else "✗"
        print(f"{status} Expected: {expected}, Got: {detected} (confidence: {conf:.2f})")
