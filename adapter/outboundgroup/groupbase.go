package outboundgroup

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/Dreamacro/clash/adapter/outbound"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/constant/provider"
	types "github.com/Dreamacro/clash/constant/provider"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/tunnel"
	"github.com/dlclark/regexp2"
	"go.uber.org/atomic"
)

type GroupBase struct {
	*outbound.Base
	filter        *regexp2.Regexp
	weightFilter  string
	providers     []provider.ProxyProvider
	failedTestMux sync.Mutex
	failedTimes   int
	failedTime    time.Time
	failedTesting *atomic.Bool
	proxies       [][]C.Proxy
	versions      []atomic.Uint32
}

type GroupBaseOption struct {
	outbound.BaseOption
	filter       string
	weightFilter string
	providers    []provider.ProxyProvider
}

func NewGroupBase(opt GroupBaseOption) *GroupBase {
	var filter *regexp2.Regexp = nil
	if opt.filter != "" {
		filter = regexp2.MustCompile(opt.filter, 0)
	}

	gb := &GroupBase{
		Base:          outbound.NewBase(opt.BaseOption),
		filter:        filter,
		weightFilter:  opt.weightFilter,
		providers:     opt.providers,
		failedTesting: atomic.NewBool(false),
	}

	gb.proxies = make([][]C.Proxy, len(opt.providers))
	gb.versions = make([]atomic.Uint32, len(opt.providers))

	return gb
}

func filterProxyByWeight(proxies []C.Proxy, weightFilter string) []C.Proxy {
	if weightFilter == "" {
		return proxies
	}
	var newProxies []C.Proxy
	re := regexp2.MustCompile(`(==|<=|!=|>=)([\d]+)`, 0)
	if m, _ := re.FindStringMatch(weightFilter); m != nil {
		gps := m.Groups()
		opt := gps[1].Captures[0].String()
		val, err := strconv.Atoi(gps[2].Captures[0].String())
		if err != nil {
			panic("invalid weight filter")
		}

		for _, p := range proxies {
			switch opt {
			case "==":
				if p.Weight() == val {
					newProxies = append(newProxies, p)
				}
			case "!=":
				if p.Weight() != val {
					newProxies = append(newProxies, p)
				}
			case ">=":
				if p.Weight() >= val {
					newProxies = append(newProxies, p)
				}
			case "<=":
				if p.Weight() <= val {
					newProxies = append(newProxies, p)
				}
			default:
				panic("invalid weight filter")
			}
		}
	} else {
		newProxies = append(newProxies, proxies...)
	}

	return newProxies
}

func (gb *GroupBase) GetProxies(touch bool) []C.Proxy {
	if gb.filter == nil {
		var proxies []C.Proxy
		for _, pd := range gb.providers {
			if touch {
				pd.Touch()
			}

			for _, p := range pd.Proxies() {
				proxies = append(proxies, p)
			}
		}
		if len(proxies) == 0 {
			return append(proxies, tunnel.Proxies()["COMPATIBLE"])
		}
		return filterProxyByWeight(proxies, gb.weightFilter)
	}

	for i, pd := range gb.providers {
		if touch {
			pd.Touch()
		}

		if pd.VehicleType() == types.Compatible {
			gb.versions[i].Store(pd.Version())
			gb.proxies[i] = pd.Proxies()
			continue
		}

		version := gb.versions[i].Load()
		if version != pd.Version() && gb.versions[i].CAS(version, pd.Version()) {
			var (
				proxies    []C.Proxy
				newProxies []C.Proxy
			)

			proxies = pd.Proxies()

			//
			if gb.filter != nil {
				for _, p := range proxies {
					if mat, _ := gb.filter.FindStringMatch(p.Name()); mat != nil {
						newProxies = append(newProxies, p)
					}
				}
			} else {
				for _, p := range proxies {
					newProxies = append(newProxies, p)
				}
			}

			gb.proxies[i] = newProxies
		}
	}

	var proxies []C.Proxy
	for _, p := range gb.proxies {
		proxies = append(proxies, p...)
	}

	if len(proxies) == 0 {
		return append(proxies, tunnel.Proxies()["COMPATIBLE"])
	}
	return filterProxyByWeight(proxies, gb.weightFilter)
}

func (gb *GroupBase) URLTest(ctx context.Context, url string) (map[string]uint16, error) {
	var wg sync.WaitGroup
	var lock sync.Mutex
	mp := map[string]uint16{}
	proxies := gb.GetProxies(false)
	for _, proxy := range proxies {
		proxy := proxy
		wg.Add(1)
		go func() {
			delay, err := proxy.URLTest(ctx, url)
			if err == nil {
				lock.Lock()
				mp[proxy.Name()] = delay
				lock.Unlock()
			}

			wg.Done()
		}()
	}
	wg.Wait()

	if len(mp) == 0 {
		return mp, fmt.Errorf("get delay: all proxies timeout")
	} else {
		return mp, nil
	}
}

func (gb *GroupBase) onDialFailed() {
	if gb.failedTesting.Load() {
		return
	}

	go func() {
		gb.failedTestMux.Lock()
		defer gb.failedTestMux.Unlock()

		gb.failedTimes++
		if gb.failedTimes == 1 {
			log.Debugln("ProxyGroup: %s first failed", gb.Name())
			gb.failedTime = time.Now()
		} else {
			if time.Since(gb.failedTime) > gb.failedTimeoutInterval() {
				gb.failedTimes = 0
				return
			}

			log.Debugln("ProxyGroup: %s failed count: %d", gb.Name(), gb.failedTimes)
			if gb.failedTimes >= gb.maxFailedTimes() {
				gb.failedTesting.Store(true)
				log.Warnln("because %s failed multiple times, active health check", gb.Name())
				wg := sync.WaitGroup{}
				for _, proxyProvider := range gb.providers {
					wg.Add(1)
					proxyProvider := proxyProvider
					go func() {
						defer wg.Done()
						proxyProvider.HealthCheck()
					}()
				}

				wg.Wait()
				gb.failedTesting.Store(false)
				gb.failedTimes = 0
			}
		}
	}()
}

func (gb *GroupBase) failedIntervalTime() int64 {
	return 5 * time.Second.Milliseconds()
}

func (gb *GroupBase) onDialSuccess() {
	if !gb.failedTesting.Load() {
		gb.failedTimes = 0
	}
}

func (gb *GroupBase) maxFailedTimes() int {
	return 5
}

func (gb *GroupBase) failedTimeoutInterval() time.Duration {
	return 5 * time.Second
}
