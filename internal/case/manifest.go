type ManifestEntry struct {
    File      string    // chemin relatif de l'artefact
    SHA256    string    // hash du fichier collecté
    Size      int64
    CollectedAt time.Time
}

func (c *Case) AddEvidence(path string) (ManifestEntry, error)  // copie + hash + enregistre
func (c *Case) Verify() (bool, error)                          // re-hhashe tout et compare
func (c *Case) SaveManifest() error                             // écrit hashes/manifest.json