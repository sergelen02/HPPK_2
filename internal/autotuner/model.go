package autotuner

// model.go
// Auto-Tuner의 입력/출력 스키마를 "타입"으로 고정하는 파일.
// - 실험 재현성(같은 입력 → 같은 출력)을 위해 필드명/타입을 변경하지 말 것.
// - JSON 태그는 configs/params/autotuner.schema.md와 1:1 대응해야 함.

type Scheme string

const (
	SchemeKEM  Scheme = "KEM"
	SchemeDS   Scheme = "DS"
	SchemeBoth Scheme = "BOTH"
)

type SecurityLevel string

const (
	LevelI   SecurityLevel = "I"
	LevelIII SecurityLevel = "III"
	LevelV   SecurityLevel = "V"
)

type HashAlg string

const (
	HashSHA256 HashAlg = "SHA-256"
	HashSHA384 HashAlg = "SHA-384"
	HashSHA512 HashAlg = "SHA-512"
)

// Segments는 DS 해시 세그먼트 개수를 표현.
// - JSON에서 "auto"를 지원하기 위해 문자열로 받되,
//   내부 계산에서는 SegmentsValue()로 정수로 해석.
type Segments string

const (
	SegmentsAuto Segments = "auto"
)

// InputConfig: configs/params/autotuner_example.json을 그대로 읽기 위한 구조체
type InputConfig struct {
	SecurityLevel  SecurityLevel `json:"security_level"`            // "I" | "III" | "V"
	Log2P          int           `json:"log2_p"`                    // bit length of field prime p
	M              int           `json:"m"`                         // number of noise vars
	Lambda         int           `json:"lambda"`                    // degree λ (usually 1)
	Scheme         Scheme        `json:"scheme,omitempty"`          // "KEM" | "DS" | "BOTH" (default BOTH)
	Hash           HashAlg        `json:"hash,omitempty"`            // DS hash (auto if empty)
	Segments       Segments       `json:"segments,omitempty"`        // "auto" or numeric string
	PKExposesMuNu  bool          `json:"pk_exposes_mu_nu,omitempty"` // DS warning trigger
	MarginBits     int           `json:"margin_bits,omitempty"`      // recommended L = min + margin (default 16)
}

// OutputReport: Auto-Tuner 실행 결과(논문/실험/코드 공용)
type OutputReport struct {
	// Core outputs
	LBitsMin         int            `json:"L_bits_min"`
	LBitsRecommended int            `json:"L_bits_recommended"`
	KBits            int            `json:"K_bits"`
	RRepr            string         `json:"R_repr"` // e.g. "2^240"

	// Reports
	SizesBytes       SizeReport      `json:"sizes_bytes"`
	SecurityEstimate SecurityEstimate `json:"security_estimate"`

	// Human-readable explanations
	Warnings []string `json:"warnings,omitempty"`

	// Paper-ready tables
	Tables TableReport `json:"tables,omitempty"`

	// Echo input for reproducibility (optional but recommended)
	InputEcho *InputConfig `json:"input_echo,omitempty"`
}

// SizeReport: 모든 크기는 "bytes" 기준
type SizeReport struct {
	PK int `json:"PK"` // public key size
	SK int `json:"SK"` // secret key size
	Sig int `json:"Sig"` // signature size (DS only)
	CT int `json:"CT"` // ciphertext size (KEM only)
}

// SecurityEstimate: 공격 복잡도/위험을 사람이 읽는 형태로 제공
type SecurityEstimate struct {
	BruteforceHiddenRing string `json:"bruteforce_hidden_ring"` // e.g. "O(2^L)"
	DSKeyRecoveryRisk    string `json:"ds_key_recovery_risk,omitempty"`
	Notes                string `json:"notes,omitempty"`
}

// TableReport: 논문에 바로 붙여넣을 수 있는 표 출력(우선 Markdown/CSV)
type TableReport struct {
	TableParamsMD string `json:"table_params_md,omitempty"`
	TableSizesMD  string `json:"table_sizes_md,omitempty"`

	TableParamsCSV string `json:"table_params_csv,omitempty"`
	TableSizesCSV  string `json:"table_sizes_csv,omitempty"`
}
