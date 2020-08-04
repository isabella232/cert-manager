// +build fips

/*
Copyright 2020 Banzai Cloud.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package util

import (
	"crypto/tls"
)

// TLSConfigDefaults sets FIPS 140-2 compatible TLS params
func TLSConfigDefaults(cfg *tls.Config) {
	if len(cfg.CipherSuites) == 0 {
		cfg.CipherSuites = []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		}
	}

	cfg.PreferServerCipherSuites = true

	if cfg.MinVersion == 0 {
		cfg.MinVersion = tls.VersionTLS12
	}

	if len(cfg.CurvePreferences) == 0 {
		cfg.CurvePreferences = []tls.CurveID{tls.CurveP256}
	}
}
