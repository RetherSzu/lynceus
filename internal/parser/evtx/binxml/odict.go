package binxml

// Dict est une table ordonnée minimale : elle remplace
// github.com/Velocidex/ordereddict, seule partie utilisée de cette dépendance.
type Dict struct {
	keys   []string
	values map[string]interface{}
}

func NewDict() *Dict { return &Dict{values: map[string]interface{}{}} }

// Set remplace la valeur d'une clé existante sans changer son rang.
func (d *Dict) Set(k string, v interface{}) {
	if _, ok := d.values[k]; !ok {
		d.keys = append(d.keys, k)
	}
	d.values[k] = v
}

func (d *Dict) Get(k string) (interface{}, bool) {
	v, ok := d.values[k]
	return v, ok
}

// Keys renvoie les clés dans l'ordre d'insertion.
func (d *Dict) Keys() []string { return d.keys }

func (d *Dict) Len() int { return len(d.keys) }
