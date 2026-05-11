import pandas as pd
import ast
from collections import Counter
from pathlib import Path

_DANGEROUS_CALLS = frozenset({
    "eval", "exec", "compile", "__import__",
})
_DANGEROUS_ATTR_CALLS = frozenset({
    "system",   # os.system
    "popen",    # os.popen
    "call", "Popen", "run", "check_output",  # subprocess
})
_SQL_SINK_CALLS = frozenset({
    "execute", "executemany", "executescript", "raw", "query", "cursor",
})
_SQL_KEYWORDS = frozenset({
    "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION",
})
_SUSPICIOUS_IMPORTS = frozenset({
    "os", "subprocess", "socket", "ctypes",
    "pickle", "marshal", "base64",
})


def get_Node_Counts(sourceCode=""):
    """
    Counts AST node types plus 7 engineered security features.
    """

    try:
        tree = ast.parse(sourceCode)
        nodeCount = [type(node).__name__ for node in ast.walk(tree)]
        counts = dict(Counter(nodeCount))

        # ── Engineered features ──────────────────────────────────────────────
        # cyclomatic complexity proxy
        cc = (
            counts.get("If", 0)
            + counts.get("For", 0)
            + counts.get("While", 0)
            + counts.get("Try", 0)
            + 1
        )
        counts["cyclomatic_complexity"] = cc

        # dangerous call count: eval/exec/compile/__import__
        n_dangerous = 0
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in _DANGEROUS_CALLS:
                    n_dangerous += 1
                elif isinstance(node.func, ast.Attribute) and node.func.attr in _DANGEROUS_ATTR_CALLS:
                    n_dangerous += 1
        counts["n_dangerous_calls"] = n_dangerous

        # suspicious import count
        n_suspicious = 0
        import_count = 0
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                import_count += len(node.names)
                for alias in node.names:
                    base = alias.name.split(".")[0]
                    if base in _SUSPICIOUS_IMPORTS:
                        n_suspicious += 1
            elif isinstance(node, ast.ImportFrom):
                import_count += 1
                if node.module:
                    base = node.module.split(".")[0]
                    if base in _SUSPICIOUS_IMPORTS:
                        n_suspicious += 1
        counts["n_suspicious_imports"] = n_suspicious
        counts["import_count"] = import_count

        # SQL sink call count + string-concat SQL detection
        n_sql_sinks = 0
        has_sql_concat = 0
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr in _SQL_SINK_CALLS:
                    n_sql_sinks += 1
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                for child in ast.walk(node):
                    if isinstance(child, ast.Constant) and isinstance(child.value, str):
                        if any(kw in child.value.upper() for kw in _SQL_KEYWORDS):
                            has_sql_concat = 1
            if isinstance(node, ast.JoinedStr):  # f-strings
                for child in ast.walk(node):
                    if isinstance(child, ast.Constant) and isinstance(child.value, str):
                        if any(kw in child.value.upper() for kw in _SQL_KEYWORDS):
                            has_sql_concat = 1
        counts["n_sql_sink_calls"] = n_sql_sinks
        counts["has_sql_concat"] = has_sql_concat

        # entropy features — delegate to entropy_profiler
        try:
            from entropy_profiler import profile_source  # type: ignore[import]
            annotations = profile_source(sourceCode)
            if annotations:
                entropies = [a.entropy for a in annotations]
                counts["max_entropy"] = max(entropies)
                counts["mean_entropy"] = sum(entropies) / len(entropies)
                counts["n_high_entropy_nodes"] = sum(1 for a in annotations if a.is_anomalous)
            else:
                counts["max_entropy"] = 0.0
                counts["mean_entropy"] = 0.0
                counts["n_high_entropy_nodes"] = 0
        except Exception:
            counts["max_entropy"] = 0.0
            counts["mean_entropy"] = 0.0
            counts["n_high_entropy_nodes"] = 0

        return counts

    except Exception as e:
        return e
    

# Load csv
inputPath = Path(Path(__file__).parent.parent / "CSV_master" / "finalData.csv")
df = pd.read_csv(inputPath)

# creates of a list of dictionaries like {Assign: 2, Call: 2, Return: 1}
featuresList = df["normalizedCode"].apply(get_Node_Counts).tolist()

# creating the dataframe and fills the empty values with 0 (eg., if one func. has an Import and another doesn't, the other function gets a Import: 0)
featuresDf = pd.DataFrame(featuresList).fillna(0)

# attaching the Labels and Source for training (for the AI Model)
featuresDf['LABEL'] = df['label']
featuresDf['SOURCE'] = df['source']


# the AI-Ready numeric matrix
outputPath = inputPath.parent / "numericFeatures.csv"
featuresDf.to_csv(outputPath, index=False)

print(f"Success! Numeric matrix created with {len(featuresDf)} samples.")
print(featuresDf.head())




