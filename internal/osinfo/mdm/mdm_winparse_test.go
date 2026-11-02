package mdm

import (
	"testing"
	"time"
)

// unenrolledPC is what a real, unenrolled Windows 11 Pro PC keeps under
// Enrollments: none of these are MDM enrollments.
var unenrolledPC = []winEnrollment{
	{id: "18DCFFD4-37D6-4BC6-87E0-4266FDBB8E49", typ: 1, state: 1},
	{id: "2648BF76-DA4B-409A-BFFA-6AF111C298A5", typ: 11, state: 1},
	{id: "8345CBE6-CEFC-462A-8219-78F3FC0377C1", providerID: "Deploy Authority", typ: 30, state: 1},
	{id: "C429BE2D-071B-4E13-B616-4141C334ECDF", providerID: "Cloud Authority", typ: 31, state: 1},
	{id: "E17005D5-A50E-4E57-BE94-1D4FA69C6F93", providerID: "Local Authority", typ: 28, state: 1},
	{id: "Context"},
}

func TestBuildWindowsInfo_NotEnrolled(t *testing.T) {
	no := false
	info := buildWindowsInfo(winFacts{editionID: "Professional", installationType: "Client", registered: &no,
		enrollments: unenrolledPC, smbiosUUID: "{65474863-FE40-43E7-0B55-C87F546C7139}"}, "mdm.example.com", time.Unix(0, 0))
	if info.Enrolled || len(info.Enrollments) != 0 || info.EnrollmentType != TypeNone {
		t.Errorf("unenrolled PC reported as enrolled: %+v", info)
	}
	if info.Eligible == nil || !*info.Eligible || info.IneligibleReason != "" || info.Edition != "Professional" {
		t.Errorf("eligibility: %+v", info)
	}
	if info.Identity.SMBIOSUUID != "65474863-fe40-43e7-0b55-c87f546c7139" {
		t.Errorf("smbios uuid %q", info.Identity.SMBIOSUUID)
	}
}

func TestBuildWindowsInfo_Eligibility(t *testing.T) {
	no := false
	for _, tc := range []struct {
		f      winFacts
		reason string
	}{
		{winFacts{editionID: "Core", installationType: "Client"}, ReasonHomeEdition},
		{winFacts{editionID: "CoreSingleLanguage", installationType: "Client"}, ReasonHomeEdition},
		{winFacts{editionID: "ServerDatacenter", installationType: "Server"}, ReasonServer},
		{winFacts{editionID: "ServerStandard", installationType: "Server Core"}, ReasonServer},
		{winFacts{editionID: "Enterprise", installationType: "Client", allowed: &no}, ReasonPolicyBlocked},
		{winFacts{editionID: "Education", installationType: "Client"}, ""},
	} {
		info := buildWindowsInfo(tc.f, "", time.Unix(0, 0))
		if info.IneligibleReason != tc.reason || *info.Eligible != (tc.reason == "") {
			t.Errorf("%s/%s: reason %q eligible %v, want %q", tc.f.editionID, tc.f.installationType, info.IneligibleReason, *info.Eligible, tc.reason)
		}
	}
}

func TestBuildWindowsInfo_Enrolled(t *testing.T) {
	yes := true
	ours := winEnrollment{id: "AAA", providerID: "SentinelOps", discoveryURL: "https://MDM.example.com/EnrollmentServer/Discovery.svc", upn: "alice@corp.com", typ: 6, state: 1}
	intune := winEnrollment{id: "BBB", providerID: "MS DM Server", discoveryURL: "https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc", typ: 13, state: 1}

	info := buildWindowsInfo(winFacts{editionID: "Enterprise", registered: &yes, enrollments: append(unenrolledPC, intune, ours)}, "mdm.example.com", time.Unix(0, 0))
	if !info.Enrolled || !info.IsOurServer || info.ServerURLHost != "mdm.example.com" || info.EnrollmentType != "mdm_only" || info.OtherMDM != "" {
		t.Errorf("ours: %+v", info)
	}
	if len(info.Enrollments) != 2 || info.Enrollments[1].UPN != "alice@corp.com" || info.Enrollments[0].Type != "entra_auto" {
		t.Errorf("enrollments: %+v", info.Enrollments)
	}

	info = buildWindowsInfo(winFacts{editionID: "Enterprise", registered: &yes, enrollments: []winEnrollment{intune}}, "mdm.example.com", time.Unix(0, 0))
	if info.IsOurServer || info.OtherMDM != "enrollment.manage.microsoft.com" || info.EnrollmentType != "entra_auto" {
		t.Errorf("intune: %+v", info)
	}
	// Without mdm_host the agent can't call it "other".
	if info := buildWindowsInfo(winFacts{registered: &yes, enrollments: []winEnrollment{intune}}, "", time.Unix(0, 0)); info.OtherMDM != "" {
		t.Errorf("other_mdm without mdm_host: %q", info.OtherMDM)
	}
	// The API says registered but no enrollment key has a discovery URL.
	if info := buildWindowsInfo(winFacts{registered: &yes}, "mdm.example.com", time.Unix(0, 0)); !info.Enrolled || info.EnrollmentType != TypeUnknown {
		t.Errorf("registered without entries: %+v", info)
	}
	// An unenrolled (state 0) entry with a URL isn't counted.
	stale := winEnrollment{id: "CCC", discoveryURL: "https://old.example.com/x", typ: 6, state: 0}
	if info := buildWindowsInfo(winFacts{enrollments: []winEnrollment{stale}}, "", time.Unix(0, 0)); info.Enrolled {
		t.Errorf("stale entry counted: %+v", info)
	}
}
