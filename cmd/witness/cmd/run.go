// Copyright 2021 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/testifysec/witness/cmd/witness/options"
	witness "github.com/testifysec/witness/pkg"
	"github.com/testifysec/witness/pkg/attestation"
	"github.com/testifysec/witness/pkg/attestation/product"
	"github.com/testifysec/witness/pkg/log"
	"github.com/testifysec/witness/pkg/rekor"
)

func RunCmd() *cobra.Command {
	o := options.RunOptions{}
	cmd := &cobra.Command{
		Use:           "run [cmd]",
		Short:         "Runs the provided command and records attestations about the execution",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRun(o, args)
		},
		Args: cobra.ArbitraryArgs,
	}

	o.AddFlags(cmd)
	return cmd
}

func runRun(ro options.RunOptions, args []string) error {
	signer, err := loadSigner(ro.KeyOptions.SpiffePath, ro.KeyOptions.KeyPath, ro.KeyOptions.CertPath, ro.KeyOptions.IntermediatePaths)
	if err != nil {
		return fmt.Errorf("failed to load signer: %w", err)
	}

	out, err := loadOutfile(ro.OutFilePath)
	if err != nil {
		return fmt.Errorf("failed to open out file: %w", err)
	}

	defer out.Close()

	result, err := witness.Run(
		ro.StepName,
		signer,
		witness.RunWithTracing(ro.Tracing),
		witness.RunWithCommand(args),
		witness.RunWithAttestors(ro.Attestations),
		witness.RunWithAttestationOpts(attestation.WithWorkingDir(ro.WorkingDir)),
	)

	if err != nil {
		return err
	}

	signedBytes, err := json.Marshal(&result.SignedEnvelope)
	if err != nil {
		return fmt.Errorf("failed to marshal envelope: %w", err)
	}

	if _, err := out.Write(signedBytes); err != nil {
		return fmt.Errorf("failed to write envelope to out file: %w", err)
	}

	rekorServer := ro.RekorServer
	if rekorServer != "" {
		verifier, err := signer.Verifier()
		if err != nil {
			return fmt.Errorf("failed to get verifier from signer: %w", err)
		}

		pubKeyBytes, err := verifier.Bytes()
		if err != nil {
			return fmt.Errorf("failed to get bytes from verifier: %w", err)
		}

		rc, err := rekor.New(rekorServer)
		if err != nil {
			return fmt.Errorf("failed to get initialize Rekor client: %w", err)
		}

		resp, err := rc.StoreArtifact(signedBytes, pubKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to store artifact in rekor: %w", err)
		}

		log.Infof("Rekor entry added at %v%v\n", rekorServer, resp.Location)
	}

	if ro.CasApiKey != "" {
		for _, att := range result.Collection.Attestations {
			if att.Type == product.Type {
				a := att.Attestation.(*product.Attestor)
				err = casNotarize(ro, a, signedBytes)
				if err != nil {
					return fmt.Errorf("error notarizing artifact; %w", err)
				}

			}
		}
	}

	return nil
}
