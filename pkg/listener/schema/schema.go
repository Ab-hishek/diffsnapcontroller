package schema

const (
	CRNameParam      = "cr-name"
	CRNamespaceParam = "cr-namespace"
)

type ChangeBlocksResponse struct {
	ChangeBlockList []ChangedBlock `json:"changeBlockList"`      //array of ChangedBlock
	NextOffset      string         `json:"nextOffset,omitempty"` // StartOffset of the next “page”.
	VolumeSize      uint64         `json:"volumeSize"`           // size of volume in bytes
	Timeout         uint64         `json:"timeout"`              //second since epoch
}

type ChangedBlock struct {
	Offset  uint64 `json:"offset"`            // logical offset
	Size    uint64 `json:"size"`              // size of the block data
	Context []byte `json:"context,omitempty"` // additional vendor specific info.  Optional.
	ZeroOut bool   `json:"zeroOut"`           // If ZeroOut is true, this block in SnapshotTarget is zero out.
	// This is for optimization to avoid data mover to transfer zero blocks.
	// Not all vendors support this zeroout.
}
