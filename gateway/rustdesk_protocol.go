package gateway

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protowire"
)

// Wire numbers are pinned to libs/hbb_common/protos/rendezvous.proto at
// 229b904508364c8997aad0fb5af57effac859f60. Unknown/encrypted signaling fails closed.
type protoField struct {
	typ   protowire.Type
	data  []byte
	value uint64
}
type protoFields map[protowire.Number]protoField

func parseFields(data []byte) (protoFields, error) {
	out := protoFields{}
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 || num < 1 || num > protowire.MaxValidNumber {
			return nil, errors.New("invalid protobuf tag")
		}
		data = data[n:]
		if _, ok := out[num]; ok {
			return nil, errors.New("duplicate protobuf field")
		}
		v := protoField{typ: typ}
		switch typ {
		case protowire.BytesType:
			v.data, n = protowire.ConsumeBytes(data)
		case protowire.VarintType:
			v.value, n = protowire.ConsumeVarint(data)
		default:
			return nil, errors.New("unsupported protobuf wire type")
		}
		if n < 0 {
			return nil, errors.New("malformed protobuf field")
		}
		out[num] = v
		data = data[n:]
	}
	return out, nil
}

func parseEnvelope(data []byte) (protowire.Number, protoFields, error) {
	outer, err := parseFields(data)
	if err != nil || len(outer) != 1 {
		return 0, nil, errDenied
	}
	for tag, v := range outer {
		if v.typ != protowire.BytesType {
			return 0, nil, errDenied
		}
		fields, err := parseFields(v.data)
		return tag, fields, err
	}
	return 0, nil, errDenied
}

func (f protoFields) text(n protowire.Number) string   { return string(f[n].data) }
func (f protoFields) number(n protowire.Number) uint64 { return f[n].value }
func bytesField(out []byte, n protowire.Number, v []byte) []byte {
	out = protowire.AppendTag(out, n, protowire.BytesType)
	return protowire.AppendBytes(out, v)
}
func textField(out []byte, n protowire.Number, v string) []byte { return bytesField(out, n, []byte(v)) }
func numberField(out []byte, n protowire.Number, v uint64) []byte {
	out = protowire.AppendTag(out, n, protowire.VarintType)
	return protowire.AppendVarint(out, v)
}
func envelope(tag protowire.Number, inner []byte) []byte { return bytesField(nil, tag, inner) }

func validFields(f protoFields, types map[protowire.Number]protowire.Type) bool {
	for n, v := range f {
		if typ, ok := types[n]; !ok || v.typ != typ {
			return false
		}
	}
	return true
}

func (s *Server) filterSignal(data []byte, peer string) ([]byte, error) {
	tag, f, err := parseEnvelope(data)
	if err != nil || f.text(1) != peer {
		return nil, errDenied
	}
	var out []byte
	switch tag {
	case 8: // PunchHoleRequest
		if !validFields(f, map[protowire.Number]protowire.Type{1: 2, 2: 0, 3: 2, 4: 0, 5: 2, 6: 2, 7: 0, 8: 0, 9: 0, 10: 2, 11: 2, 12: 2}) || f.number(4) != 0 || f.text(5) != "" || f.number(7) != 0 || f.number(9) != 0 || len(f[10].data) > 0 || f.text(11) != "" || f.text(12) != "" {
			return nil, errDenied
		}
		out = textField(out, 1, peer)
		out = numberField(out, 2, 2) // symmetric NAT: never request direct transport
		out = textField(out, 3, s.cfg.ServerKey)
		out = textField(out, 6, f.text(6))
		out = numberField(out, 8, 1)
	case 18: // RequestRelay, sent to hbbs
		if !validFields(f, map[protowire.Number]protowire.Type{1: 2, 2: 2, 3: 2, 4: 2, 5: 0, 6: 2, 7: 0, 8: 2, 9: 2, 10: 2, 11: 2}) || f.number(7) != 0 || f.text(8) != "" || len(f[9].data) > 0 || len(f[10].data) > 0 || f.text(11) != "" {
			return nil, errDenied
		}
		out = textField(out, 1, peer)
		// hbbr pairs by UUID alone. Never allow a browser-selected UUID to collide
		// with a different device or an already active relay.
		out = textField(out, 2, uuid.NewString())
		out = numberField(out, 5, f.number(5))
		out = textField(out, 6, s.cfg.ServerKey)
	default:
		return nil, fmt.Errorf("signaling message %d: %w", tag, errDenied)
	}
	return envelope(tag, out), nil
}

func (s *Server) filterSignalResponse(data []byte, v remoteSession, peer string) ([]byte, error) {
	tag, f, err := parseEnvelope(data)
	if err != nil {
		return nil, errDenied
	}
	var out []byte
	relayURL := s.cfg.Origin + "/ws/remote/" + v.ID + "/relay"
	if len(relayURL) > 5 && relayURL[:5] == "https" {
		relayURL = "wss" + relayURL[5:]
	} else {
		relayURL = "ws" + relayURL[4:]
	}
	switch tag {
	case 19: // RelayResponse
		if !validFields(f, map[protowire.Number]protowire.Type{1: 2, 2: 2, 3: 2, 4: 2, 5: 2, 6: 2, 7: 2, 9: 0, 10: 2, 11: 0, 12: 2}) || (f.text(4) != "" && f.text(4) != peer) || (len(f[4].data) > 0 && len(f[5].data) > 0) {
			return nil, errDenied
		}
		if f.text(6) == "" {
			if _, err := uuid.Parse(f.text(2)); err != nil {
				return nil, errDenied
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			if _, err := s.validSessionLocked(v.ID, v.Owner, v.DeviceID); err != nil {
				return nil, err
			}
			if _, exists := s.tickets[f.text(2)]; exists {
				return nil, errDenied
			}
			count := 0
			for _, t := range s.tickets {
				if t.Session == v.ID {
					count++
				}
			}
			if count >= 4 {
				return nil, errDenied
			}
			expires := time.Now().Add(30 * time.Second)
			if v.ExpiresAt.Before(expires) {
				expires = v.ExpiresAt
			}
			s.tickets[f.text(2)] = relayTicket{Session: v.ID, Device: v.DeviceID, Expires: expires}
			out = textField(out, 2, f.text(2))
			out = textField(out, 3, relayURL)
			if len(f[5].data) > 0 {
				out = bytesField(out, 5, f[5].data)
			} else {
				out = textField(out, 4, peer)
			}
		} else {
			out = textField(out, 6, f.text(6))
		}
		out = textField(out, 7, f.text(7))
	case 11: // PunchHoleResponse: strip all socket/ICE/UPnP information.
		if !validFields(f, map[protowire.Number]protowire.Type{1: 2, 2: 2, 3: 0, 4: 2, 5: 0, 6: 0, 7: 2, 8: 0, 9: 0, 10: 0, 11: 2, 12: 2}) {
			return nil, errDenied
		}
		out = bytesField(out, 2, f[2].data)
		out = numberField(out, 3, f.number(3))
		out = textField(out, 4, relayURL)
		out = numberField(out, 5, 2)
		out = textField(out, 7, f.text(7))
	default:
		return nil, errDenied
	}
	return envelope(tag, out), nil
}

func (s *Server) filterRelayHandshake(data []byte, v remoteSession, peer string) ([]byte, error) {
	tag, f, err := parseEnvelope(data)
	if err != nil || tag != 18 || !validFields(f, map[protowire.Number]protowire.Type{1: 2, 2: 2, 5: 0, 6: 2, 7: 0}) || f.text(1) != peer || f.number(7) != 0 {
		return nil, errDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.validSessionLocked(v.ID, v.Owner, v.DeviceID); err != nil {
		return nil, err
	}
	ticket, ok := s.tickets[f.text(2)]
	if !ok || ticket.Session != v.ID || ticket.Device != v.DeviceID || !time.Now().Before(ticket.Expires) {
		return nil, errDenied
	}
	delete(s.tickets, f.text(2))
	out := textField(nil, 1, peer)
	out = textField(out, 2, f.text(2))
	out = numberField(out, 5, f.number(5))
	out = textField(out, 6, s.cfg.ServerKey)
	return envelope(18, out), nil
}
