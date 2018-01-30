package firebase

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"

	jwt "github.com/dgrijalva/jwt-go"
)

var cache = newKeyCache()

// Keyfunc returns a JWT validator suitable for validating Firebase tokens destined for the given project.
// Fetches the Firebase public keys using the provided *http.Client.
func Keyfunc(projectID string, client *http.Client) jwt.Keyfunc {
	iss := "https://securetoken.google.com/" + projectID
	return func(token *jwt.Token) (interface{}, error) {
		if token.Header["alg"] != "RS256" {
			return nil, fmt.Errorf("alg is not RS256")
		}

		claims := token.Claims.(jwt.MapClaims)

		if claims["iss"] != iss {
			return nil, fmt.Errorf("incorrect iss")
		}

		if claims["aud"] != projectID {
			return nil, fmt.Errorf("incorrect aud")
		}

		kid := token.Header["kid"].(string)

		cache.RLock()
		key, ok := cache.keys[kid]
		cache.RUnlock()
		if !ok { // New key?  Refresh list of keys.
			err := getKeys(client, cache)
			if err != nil {
				return nil, err
			}

			cache.RLock()
			key, ok = cache.keys[kid]
			cache.RUnlock()
			if !ok {
				return nil, fmt.Errorf("key for %q not found", kid)
			}
		}

		return key, nil
	}
}

// keyCache maintains a mapping from key id to public key
type keyCache struct {
	keys map[string]*rsa.PublicKey
	sync.RWMutex
}

// newKeyCache initializes a new keyCache
func newKeyCache() *keyCache {
	return &keyCache{keys: map[string]*rsa.PublicKey{}}
}

// getKeys fetches the Firebase token public keys from Google and updates the provided keyCache
func getKeys(client *http.Client, cache *keyCache) error {
	cache.Lock()
	defer cache.Unlock()

	keys := map[string]string{}
	res, err := client.Get("https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com")
	if err != nil {
		return err
	}
	body, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return err
	}

	err = json.Unmarshal(body, &keys)
	if err != nil {
		return err
	}

	kc := make(map[string]*rsa.PublicKey, len(keys))
	for k, v := range keys {
		key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(v))
		if err != nil {
			return err
		}
		kc[k] = key
	}

	cache.keys = kc

	return nil
}
