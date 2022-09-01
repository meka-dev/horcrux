package signer

import (
	"sync"

	"github.com/meka-dev/mekatek-go/mekabuild"
	"github.com/tendermint/tendermint/crypto"
	tmProto "github.com/tendermint/tendermint/proto/tendermint/types"
	tm "github.com/tendermint/tendermint/types"
)

// PvGuard guards access to an underlying PrivValidator by using mutexes
// for each of the PrivValidator interface functions
type PvGuard struct {
	PrivValidator tm.PrivValidator
	pvMutex       sync.Mutex
}

// GetPubKey implements types.PrivValidator
func (pv *PvGuard) GetPubKey() (crypto.PubKey, error) {
	pv.pvMutex.Lock()
	defer pv.pvMutex.Unlock()
	return pv.PrivValidator.GetPubKey()
}

// SignVote implements types.PrivValidator
func (pv *PvGuard) SignVote(chainID string, vote *tmProto.Vote) error {
	pv.pvMutex.Lock()
	defer pv.pvMutex.Unlock()
	return pv.PrivValidator.SignVote(chainID, vote)
}

// SignProposal implements types.PrivValidator
func (pv *PvGuard) SignProposal(chainID string, proposal *tmProto.Proposal) error {
	pv.pvMutex.Lock()
	defer pv.pvMutex.Unlock()
	return pv.PrivValidator.SignProposal(chainID, proposal)
}

func (pv *PvGuard) SignMekatekBuildBlockRequest(req *mekabuild.BuildBlockRequest) error {
	pv.pvMutex.Lock()
	defer pv.pvMutex.Unlock()
	return pv.PrivValidator.SignMekatekBuildBlockRequest(req)
}

func (pv *PvGuard) SignMekatekRegisterChallenge(c *mekabuild.RegisterChallenge) error {
	pv.pvMutex.Lock()
	defer pv.pvMutex.Unlock()
	return pv.PrivValidator.SignMekatekRegisterChallenge(c)
}
