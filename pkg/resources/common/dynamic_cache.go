package common

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/cache"
)

// DynamicCacheSyncTimeout bounds how long WaitForDynamicCache waits for a cache to sync.
var DynamicCacheSyncTimeout = 10 * time.Second

// DynamicCacheGetter is the part of lasso's dynamic.Controller that reports on a kind's cache.
type DynamicCacheGetter interface {
	GetCache(ctx context.Context, gvk schema.GroupVersionKind) (cache.SharedIndexInformer, bool, error)
}

// WaitForDynamicCache waits for the dynamic controller's cache of gvk to sync, for up to
// DynamicCacheSyncTimeout. The controller registers an informer the first time a kind is asked for,
// so the first requests after the webhook starts can find it still syncing, and an unsynced cache
// reads as empty. It returns an error, for the request to fail and the client to retry, if the cache
// doesn't sync in time.
func WaitForDynamicCache(ctx context.Context, caches DynamicCacheGetter, gvk schema.GroupVersionKind) error {
	informer, synced, err := caches.GetCache(ctx, gvk)
	if err != nil {
		return fmt.Errorf("failed to get the %s cache: %w", gvk.Kind, err)
	}
	if synced {
		return nil
	}

	waitCtx, cancel := context.WithTimeout(ctx, DynamicCacheSyncTimeout)
	defer cancel()
	if !cache.WaitForCacheSync(waitCtx.Done(), informer.HasSynced) {
		return fmt.Errorf("timed out waiting for the %s cache to sync, retry the request", gvk.Kind)
	}
	return nil
}
