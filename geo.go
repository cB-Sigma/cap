package cap

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// CAP writes coordinates as WGS 84 "latitude,longitude" pairs; GeoJSON
// (RFC 7946) writes positions as [longitude, latitude].

// ParsePolygon reads a CAP polygon: at least four space-separated
// "lat,lon" pairs whose first and last are the same point. It returns the
// ring as GeoJSON positions.
func ParsePolygon(s string) ([][]float64, error) {
	f := strings.Fields(s)
	if len(f) < 4 {
		return nil, fmt.Errorf("a polygon needs at least 4 points, this one has %d", len(f))
	}
	ring := make([][]float64, 0, len(f))
	for _, p := range f {
		lat, lon, err := parsePoint(p)
		if err != nil {
			return nil, err
		}
		ring = append(ring, []float64{lon, lat})
	}
	first, last := ring[0], ring[len(ring)-1]
	if first[0] != last[0] || first[1] != last[1] {
		return nil, fmt.Errorf("a polygon's first and last points must be the same")
	}
	return ring, nil
}

// ParseCircle reads a CAP circle "lat,lon radius" (radius in km).
func ParseCircle(s string) (center []float64, radiusKm float64, err error) {
	f := strings.Fields(s)
	if len(f) != 2 {
		return nil, 0, fmt.Errorf("circle %q is not \"lat,lon radius\"", s)
	}
	lat, lon, err := parsePoint(f[0])
	if err != nil {
		return nil, 0, err
	}
	r, err := strconv.ParseFloat(f[1], 64)
	if err != nil || r < 0 || math.IsNaN(r) || math.IsInf(r, 0) {
		return nil, 0, fmt.Errorf("circle radius %q is not a distance in km", f[1])
	}
	return []float64{lon, lat}, r, nil
}

func parsePoint(p string) (lat, lon float64, err error) {
	ll := strings.Split(p, ",")
	if len(ll) != 2 {
		return 0, 0, fmt.Errorf("point %q is not \"lat,lon\"", p)
	}
	lat, err1 := strconv.ParseFloat(ll[0], 64)
	lon, err2 := strconv.ParseFloat(ll[1], 64)
	if err1 != nil || err2 != nil || lat < -90 || lat > 90 || lon < -180 || lon > 180 {
		return 0, 0, fmt.Errorf("point %q is not a WGS 84 latitude,longitude", p)
	}
	return lat, lon, nil
}

// circleSegments is how many sides the polygon approximating a circle has.
const circleSegments = 32

// CirclePolygon approximates a circle as a closed GeoJSON ring (spherical
// Earth, 6371 km).
func CirclePolygon(center []float64, radiusKm float64) [][]float64 {
	return CirclePolygonN(center, radiusKm, circleSegments)
}

// CirclePolygonN is CirclePolygon with n sides (at least 3; 32 when n is
// smaller), for maps that need a finer or coarser outline.
func CirclePolygonN(center []float64, radiusKm float64, n int) [][]float64 {
	if n < 3 {
		n = circleSegments
	}
	const earth = 6371.0
	lon0, lat0 := center[0]*math.Pi/180, center[1]*math.Pi/180
	d := radiusKm / earth
	ring := make([][]float64, 0, n+1)
	for i := 0; i < n; i++ {
		b := 2 * math.Pi * float64(i) / float64(n)
		lat := math.Asin(math.Sin(lat0)*math.Cos(d) + math.Cos(lat0)*math.Sin(d)*math.Cos(b))
		lon := lon0 + math.Atan2(math.Sin(b)*math.Sin(d)*math.Cos(lat0), math.Cos(d)-math.Sin(lat0)*math.Sin(lat))
		ring = append(ring, []float64{round6(lon * 180 / math.Pi), round6(lat * 180 / math.Pi)})
	}
	return append(ring, ring[0])
}

func round6(v float64) float64 { return math.Round(v*1e6) / 1e6 }

// GeoJSON renders every area of the alert as a GeoJSON FeatureCollection:
// one Feature per area, with a Polygon, a MultiPolygon, or no geometry when
// the area is described by geocodes only. Circles become 32-sided polygons
// and keep their centre and radius in the properties.
func (a *Alert) GeoJSON() map[string]any { return a.GeoJSONWith(circleSegments) }

// GeoJSONWith is GeoJSON with circles drawn as polygons of the given
// number of sides.
func (a *Alert) GeoJSONWith(segments int) map[string]any {
	features := []any{}
	for _, in := range a.Info {
		for _, ar := range in.Area {
			var polys [][][][]float64
			var circles []any
			for _, pg := range ar.Polygon {
				if ring, err := ParsePolygon(pg); err == nil {
					polys = append(polys, [][][]float64{ring})
				}
			}
			for _, c := range ar.Circle {
				if center, r, err := ParseCircle(c); err == nil {
					polys = append(polys, [][][]float64{CirclePolygonN(center, r, segments)})
					circles = append(circles, map[string]any{"center": center, "radiusKm": r})
				}
			}
			props := map[string]any{"areaDesc": ar.AreaDesc}
			if in.Language != "" {
				props["language"] = in.Language
			}
			if len(ar.Geocode) > 0 {
				gc := map[string]any{}
				for _, g := range ar.Geocode {
					gc[g.ValueName] = g.Value
				}
				props["geocodes"] = gc
			}
			if len(circles) > 0 {
				props["circles"] = circles
			}
			if ar.Altitude != "" {
				props["altitude"] = ar.Altitude
			}
			if ar.Ceiling != "" {
				props["ceiling"] = ar.Ceiling
			}
			var geom any
			switch len(polys) {
			case 0:
			case 1:
				geom = map[string]any{"type": "Polygon", "coordinates": polys[0]}
			default:
				geom = map[string]any{"type": "MultiPolygon", "coordinates": polys}
			}
			features = append(features, map[string]any{"type": "Feature", "geometry": geom, "properties": props})
		}
	}
	return map[string]any{"type": "FeatureCollection", "features": features}
}
