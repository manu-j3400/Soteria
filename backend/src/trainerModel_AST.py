import warnings
import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, ExtraTreesClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix
from joblib import dump
from pathlib import Path



def build_ensemble():
    """RF + GB + ET + LR soft-voting ensemble used for acidModel.pkl."""
    
    # Define multiple base classifiers
    rf = RandomForestClassifier(
        n_estimators=300, 
        max_depth=15, 
        min_samples_leaf=1, 
        min_samples_split=2,
        class_weight='balanced',
        random_state=42
    )
    
    gb = GradientBoostingClassifier(
        n_estimators=200,
        max_depth=5,
        learning_rate=0.1,
        random_state=42
    )
    
    # ExtraTreesClassifier: tree diversity for the ensemble
    et = ExtraTreesClassifier(
        n_estimators=300,
        max_depth=15,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1,
    )

    # LogisticRegression: liblinear uses coordinate descent — no matrix overflow
    lr_pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('lr', LogisticRegression(
            class_weight='balanced',
            max_iter=5000,
            random_state=42,
            solver='liblinear',  # coordinate descent, numerically stable on sparse binary features
            C=0.5,
        ))
    ])

    # VotingClassifier: RF + GB + ET + LR for broad coverage
    ensemble = VotingClassifier(
        estimators=[
            ('rf', rf),
            ('gb', gb),
            ('et', et),
            ('lr', lr_pipeline),
        ],
        voting='soft',
        n_jobs=-1
    )
    return ensemble


def modelTrainer(data_path = str(Path(__file__).parent.parent / "CSV_master" / "numericFeatures.csv")):
    df = pd.read_csv(data_path)

    # Prepare X(features) and y (Target Label)
    X = df.drop(['LABEL', 'SOURCE'], axis=1)
    y = df['LABEL']

    # Reduced test size for more training data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.15, random_state=42, stratify=y)

    print("  Building Ensemble Model...  ")
    ensemble = build_ensemble()

    # Suppress sklearn internal matmul overflow warnings from LR predict_proba
    # (known sklearn/numpy compat issue on Python 3.14; model validity unaffected)
    _filter = warnings.filterwarnings("ignore", category=RuntimeWarning, module="sklearn")

    # Cross-validation score
    print("  Running 5-fold Cross-Validation...  ")
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=RuntimeWarning)
        cv_scores = cross_val_score(ensemble, X_train, y_train, cv=5, scoring='accuracy')
    print(f"CV Accuracy: {cv_scores.mean():.2%} (+/- {cv_scores.std()*2:.2%})")

    # Fit the ensemble
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=RuntimeWarning)
        ensemble.fit(X_train, y_train)

    # PREDICTION TIME
    y_predictions = ensemble.predict(X_test)

    print("Model Evaluation")
    print(confusion_matrix(y_test, y_predictions))
    print(classification_report(y_test, y_predictions))

    # saving the model for later use
    modelDir = Path(Path(__file__).parent.parent / "ML_master")
    modelDir.mkdir(parents=True, exist_ok=True)

    modelPath = modelDir / 'acidModel.pkl'
    dump(ensemble, modelPath)

    print(f"Model exported to: {modelPath}")




