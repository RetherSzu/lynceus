type Case struct {
    ID          string    // "CASE-2027-001"
    Hostname    string    // "WIN-CLIENT01"
    Analyst     string    // "dfir-team"
    CreatedAt   time.Time
    ToolVersion string    // la fameuse variable main.version
    BaseDir     string    // chemin du dossier case/
}

func New(hostname, analyst string) (*Case, error)   // génère l'ID, crée l'arborescence
func (c *Case) Load(path string) (*Case, error)     // rouvre une affaire existante
func (c *Case) Dir(kind string) string              // c.Dir("evidence") → cases/X/evidence/