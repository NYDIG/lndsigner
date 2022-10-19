// Copyright (C) 2013-2017 The btcsuite developers
// Copyright (C) 2015-2016 The Decred developers
// Copyright (C) 2015-2022 Lightning Labs and The Lightning Network Developers
// Copyright (C) 2022 Bottlepay and The Lightning Network Developers

package policy

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/davecgh/go-spew/spew"
)

func TestDeriveOurScriptForCommit(t *testing.T) {
	testCases := []struct {
		name         string
		wantScript   []byte
		channel      *chanInfo
		pubKeyCoords []string
	}{
		{
			name: "ver 3",
			wantScript: []byte{0x00, 0x20, 0x70, 0x9a, 0x68, 0xfe,
				0x69, 0xb6, 0xa4, 0x5e, 0x03, 0xa3, 0x11, 0xc8,
				0x77, 0x4f, 0xf3, 0xb1, 0xe2, 0x08, 0x95, 0x17,
				0x2f, 0x32, 0x55, 0x92, 0x10, 0x39, 0xfd, 0xfe,
				0x2c, 0x00, 0xad, 0xec},
			channel: &chanInfo{
				ver: 3,
			},
			pubKeyCoords: []string{
				// Local multisig X
				"ef18f700eb241fe9b325caffea61b172f009ed099b6879531f593d03379cf04e",
				// Local multisig Y
				"dad02c9db30dc65a4f8015fa9d709b91a4656706f5393a6fd895e0b2f5fd3665",
				// Local revocation X
				"78b71bb27b6e9841bbfd036f1d4728235c439cacf83fe87159e460621a75e338",
				// Local revocation Y
				"d77d89f429d7cadd8ca485037194a5df150ad7a13c0fe050fdc00959d746bade",
				// Local payment X
				"560c0196f51c38a358aae548b10a910bd8167128613bf0527d65beb79889d223",
				// Local payment Y
				"6f5b9b826393c8a91328e887b007be17f1dee44b4526baa31b647dda9a15d288",
				// Local delay X
				"6a31a70440ad93511a78ee844670e69ed2525567a34d373762dd2f56bd24a612",
				// Local delay Y
				"214cba8d2cbb42d6d33f0972f97355494848751607de5ee12a0b29a46c2da7aa",
				// Local HTLC X
				"113cac1ea067373bf2a09d4bb6c0e46db9e71d8ed36716be309739526b72f25a",
				// Local HTLC Y
				"d68a9d13f850c23c24308d1d2dfdf3b8e67e7cb54382395e96a0cb3cfc54fc7f",
				// Remote multisig X
				"95e332c87d7b889d0485bc606d8b416257c0d538c94549baced2ca01b105736f",
				// Remote multisig Y
				"0c56910d0af87207719afeb858f8bcb56c0c9e34a74f75124cad880c8d8946a2",
				// Remote revocation X
				"45f7de739a90e85653e3efbc3ce98a17bb4d92423cee223273425bed3b4eb966",
				// Remote revocation Y
				"2c01d0ca76f4318eed065ad9664a2f688c3b4969694d6d5e881eadb57897ccdc",
				// Remote payment X
				"c0812b2863b082c802118b39566510eaf463122adc92505af31d0f64ddde426f",
				// Remote payment Y
				"d09942404cf6934e521b957feb2c5274d57346a2b90791af22497b4c7467a5e6",
				// Remote delay X
				"59f048efc8b408c4e3dfe3a61fd293bc5b1d4780f5609519fa04679e4a3c3ba3",
				// Remote delay Y
				"bf770f6fe33945b17c07e3c55a8c4c2adb64efa4a28f163e40df442e4014376e",
				// Remote HTLC X
				"616a433042c9601f3fbf11bbc06b26afdfca05b5644641f369730945a9c91a10",
				// Remote HTLC Y
				"f3689fea433b7594bb6e929f69d9f1c375615ff407ccf9416fd497ee4f5e2f98",
				// SHA Chain X
				"c2726015173ebf8956f500d124dc0578ca402a707db880251389dca0835c884f",
				// SHA Chain Y
				"5afe573a81fa7f605a5c9fad45e8fbf9b5ee76444baa9cc5c6cd41ae0839222a",
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			for idx, pub := range []**btcec.PublicKey{
				&testCase.channel.localMultisig.PubKey,
				&testCase.channel.localRevocation.PubKey,
				&testCase.channel.localPayment.PubKey,
				&testCase.channel.localDelay.PubKey,
				&testCase.channel.localHTLC.PubKey,
				&testCase.channel.remoteMultisig,
				&testCase.channel.remoteRevocation,
				&testCase.channel.remotePayment,
				&testCase.channel.remoteDelay,
				&testCase.channel.remoteHTLC,
				&testCase.channel.shaChain.PubKey,
			} {
				xBytes, err := hex.DecodeString(
					testCase.pubKeyCoords[idx*2],
				)
				if err != nil {
					t.Fatalf("Couldn't decode hex for X "+
						"coord: %s", err)
				}

				yBytes, err := hex.DecodeString(
					testCase.pubKeyCoords[(idx*2)+1],
				)
				if err != nil {
					t.Fatalf("Couldn't decode hex for Y "+
						"coord: %s", err)
				}

				var x, y btcec.FieldVal

				overflow := x.SetByteSlice(xBytes)
				if overflow {
					t.Fatalf("Overflowed X coord")
				}

				overflow = y.SetByteSlice(yBytes)
				if overflow {
					t.Fatalf("Overflowed Y coord")
				}

				*pub = btcec.NewPublicKey(&x, &y)
			}

			t.Logf("Channel: %s", spew.Sdump(testCase.channel))

			p2wsh, err := testCase.channel.ourScriptForCommit()
			if err != nil {
				t.Fatalf("Couldn't get script for commit: %s",
					err)
			}

			if !bytes.Equal(p2wsh, testCase.wantScript) {
				t.Fatalf("Scripts aren't equal\nGot script:  "+
					"%x\nWant script: %x", p2wsh,
					testCase.wantScript)
			}
		})
	}

}
