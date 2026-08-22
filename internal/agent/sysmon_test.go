package agent

import "testing"

func TestParseSysmonEventsPreservesRawAndCursor(t *testing.T) {
	document := []byte(`<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventRecordID>41</EventRecordID><Computer>DC01</Computer><TimeCreated SystemTime="2026-08-23T08:09:10.123Z" /></System></Event><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventRecordID>42</EventRecordID><Computer>DC01</Computer><TimeCreated SystemTime="2026-08-23T08:09:11.123Z" /></System></Event></Events>`)
	events, err := parseSysmonEvents(document, 41)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Cursor != 42 || events[0].EventID == "" {
		t.Fatalf("unexpected events: %+v", events)
	}
	if string(events[0].Payload) != `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventRecordID>42</EventRecordID><Computer>DC01</Computer><TimeCreated SystemTime="2026-08-23T08:09:11.123Z" /></System></Event>` {
		t.Fatalf("raw event changed: %s", events[0].Payload)
	}
}
