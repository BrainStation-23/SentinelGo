// MIT License
//
// Copyright (c) SentinelGo Authors
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Package m1cpu is a permissively-licensed stub that replaces github.com/shoenig/go-m1cpu
// (MPL-2.0). It reports IsAppleSilicon()=false on all platforms, causing gopsutil to fall
// back to standard sysctl-based CPU queries. All other functions panic if called, matching
// the behaviour of the original package's non-darwin/arm64 build.
package m1cpu

// IsAppleSilicon returns false on all platforms in this stub.
func IsAppleSilicon() bool {
	return false
}

// PCoreHz requires darwin/arm64.
func PCoreHz() uint64 {
	panic("m1cpu stub: not a darwin/arm64 system")
}

// ECoreHz requires darwin/arm64.
func ECoreHz() uint64 {
	panic("m1cpu stub: not a darwin/arm64 system")
}

// PCoreGHz requires darwin/arm64.
func PCoreGHz() float64 {
	panic("m1cpu stub: not a darwin/arm64 system")
}

// ECoreGHz requires darwin/arm64.
func ECoreGHz() float64 {
	panic("m1cpu stub: not a darwin/arm64 system")
}

// PCoreCount requires darwin/arm64.
func PCoreCount() int {
	panic("m1cpu stub: not a darwin/arm64 system")
}

// ECoreCount requires darwin/arm64.
func ECoreCount() int {
	panic("m1cpu stub: not a darwin/arm64 system")
}

// PCoreCache requires darwin/arm64.
func PCoreCache() (int, int, int) {
	panic("m1cpu stub: not a darwin/arm64 system")
}

// ECoreCache requires darwin/arm64.
func ECoreCache() (int, int, int) {
	panic("m1cpu stub: not a darwin/arm64 system")
}

// ModelName requires darwin/arm64.
func ModelName() string {
	panic("m1cpu stub: not a darwin/arm64 system")
}
