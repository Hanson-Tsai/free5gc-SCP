package detector

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"

	"github.com/free5gc/UeauCommon"
	"github.com/free5gc/milenage"
	"github.com/free5gc/openapi/models"
	suciLib "github.com/free5gc/util_3gpp/suci"
)

// Extract SUPI from SUCI
func extractSupi(suci string) (supi string, err error) {
	return suciLib.ToSupi(suci, nil)
}

// Generate XRES, SQNxorAK, CK, IK, AUTN from UE authentication subscription data
func retrieveBasicDeriveFactor(authSubs *models.AuthenticationSubscription, randHex string) (XRES []byte, SQNxorAK []byte, CK []byte, IK []byte, AUTN []byte) {
	secretKey, _ := hex.DecodeString(authSubs.PermanentKey.PermanentKeyValue)
	var op, opc []byte
	if authSubs.Opc != nil && authSubs.Opc.OpcValue != "" {
		opcStr := authSubs.Opc.OpcValue
		opc, _ = hex.DecodeString(opcStr)
	} else {
		opStr := authSubs.Milenage.Op.OpValue
		op, _ = hex.DecodeString(opStr)
		opc, _ = milenage.GenerateOPC(secretKey, op)
	}
	rand, _ := hex.DecodeString(randHex)
	sqn, _ := hex.DecodeString(authSubs.SequenceNumber)
	AMF, _ := hex.DecodeString(authSubs.AuthenticationManagementField)

	macA, macS := make([]byte, 8), make([]byte, 8)
	XRES = make([]byte, 8)
	CK, IK = make([]byte, 16), make([]byte, 16)
	AK, AKstar := make([]byte, 6), make([]byte, 6)

	milenage.F1(opc, secretKey, rand, sqn, AMF, macA, macS)
	milenage.F2345(opc, secretKey, rand, XRES, CK, IK, AK, AKstar)

	SQNxorAK = make([]byte, 6)
	for i := 0; i < 6; i++ {
		SQNxorAK[i] = sqn[i] ^ AK[i]
	}
	AUTN = append(append(SQNxorAK, AMF...), macA...)

	return
}

// Generate XRES*
// For parameter FC, it should be a hexadecimal string
// e.g. for value 0x10, FC should be "10"
func retrieveXresStar(key []byte, FC string, P0 []byte, P1 []byte, P2 []byte) (xresStar []byte) {
	kdfValForXresStar := UeauCommon.GetKDFValue(
		key, FC, P0, UeauCommon.KDFLen(P0), P1, UeauCommon.KDFLen(P1), P2, UeauCommon.KDFLen(P2))
	xresStar = kdfValForXresStar[len(kdfValForXresStar)/2:]
	return
}

// Generate HXRES*
func retrieveHxresStar(xresStar []byte) (hxresStar []byte) {
	hxresStarAll := sha256.Sum256(xresStar)
	hxresStar = hxresStarAll[16:]
	return
}

// Generate Kausf for 5G AKA
// For parameter FC, it should be a hexadecimal string
// e.g. for value 0x10, FC should be "10"
func retrieve5GAkaKausf(key []byte, FC string, P0 []byte, P1 []byte) (kausf []byte) {
	kausf = UeauCommon.GetKDFValue(key, FC, P0, UeauCommon.KDFLen(P0), P1, UeauCommon.KDFLen(P1))
	return
}

// Generate Kseaf
// For parameter FC, it should be a hexadecimal string
// e.g. for value 0x10, FC should be "10"
func retrieveKseaf(key []byte, FC string, P0 []byte) (kseaf []byte) {
	kseaf = UeauCommon.GetKDFValue(key, UeauCommon.FC_FOR_KSEAF_DERIVATION, P0, UeauCommon.KDFLen(P0))
	return
}

// Generate CK', IK'
// For parameter FC, it should be a hexadecimal string
// e.g. for value 0x10, FC should be "10"
func retrieveCkPrimeAndIkPrime(key []byte, FC string, P0 []byte, P1 []byte) (ckPrime []byte, ikPrime []byte) {
	kdfVal := UeauCommon.GetKDFValue(key, FC, P0, UeauCommon.KDFLen(P0), P1, UeauCommon.KDFLen(P1))
	ckPrime = kdfVal[:len(kdfVal)/2]
	ikPrime = kdfVal[len(kdfVal)/2:]
	return
}

// Genearate Kausf for EAP-AKA'
func retrieveEapAkaPrimeKausf(CK []byte, IK []byte, identity string) (kausf []byte) {
	_, _, _, _, EMSK := eapAkaPrimePrf(IK, CK, identity)
	return EMSK[:32]
}

func eapAkaPrimePrf(IK []byte, CK []byte, identity string) ([]byte, []byte, []byte, []byte, []byte) {
	key := append(IK, CK...)
	sBase := []byte("EAP-AKA'" + identity)

	MK := []byte("")
	prev := []byte("")
	prfRounds := 208/32 + 1
	for i := 0; i < prfRounds; i++ {
		// Create a new HMAC by defining the hash type and the key (as byte array)
		h := hmac.New(sha256.New, key)

		hexNum := (byte)(i + 1)
		ap := append(sBase, hexNum)
		s := append(prev, ap...)

		// Write Data to it
		h.Write(s)

		// Get result
		sha := h.Sum(nil)
		MK = append(MK, sha...)
		prev = sha
	}

	K_encr := MK[0:16]  // 0..127
	K_aut := MK[16:48]  // 128..383
	K_re := MK[48:80]   // 384..639
	MSK := MK[80:144]   // 640..1151
	EMSK := MK[144:208] // 1152..1663
	return K_encr, K_aut, K_re, MSK, EMSK
}
