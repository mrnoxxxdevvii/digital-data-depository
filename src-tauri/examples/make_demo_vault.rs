use std::path::PathBuf;

use ddd::vault::create_depository;

const PASSWORD: &str = "demo-vault-password-2026";

fn main() {
    let path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("Demo Depository.ddd"));
    if path.exists() {
        std::fs::remove_file(&path).expect("remove old demo vault");
    }

    let mut session = create_depository(&path, PASSWORD).expect("create demo vault");

    let files: Vec<(&str, Vec<u8>)> = vec![
        ("archive-sample.bin", binary_sample()),
        ("architecture.svg", svg_diagram()),
        (
            "project-brief.txt",
            paragraph_report(
                "PROJECT BRIEF - SAMPLE DOCUMENT",
                "This file exists only to demonstrate the depository. Every name, number and note below is fictional.",
                6,
            ),
        ),
        (
            "field-notes.md",
            markdown_notes(),
        ),
        (
            "budget-draft.csv",
            csv_table(),
        ),
        (
            "site-inventory.json",
            json_inventory(),
        ),
        (
            "meeting-minutes.txt",
            paragraph_report(
                "MEETING MINUTES - SAMPLE DOCUMENT",
                "Placeholder content for a fictional working session. No real people, organizations or locations are referenced.",
                4,
            ),
        ),
        (
            "archive-index.txt",
            archive_index(),
        ),
        (
            "release-checklist.md",
            checklist(),
        ),
    ];

    for (name, content) in files {
        session.add_file(name, &content).expect("add demo file");
    }

    let snapshot = session.snapshot();
    println!(
        "{} entries, {} bytes: {}",
        snapshot.entries.len(),
        snapshot.total_size,
        path.display()
    );
}

fn svg_diagram() -> Vec<u8> {
    String::from(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"800\" height=\"450\" viewBox=\"0 0 800 450\">\n\
         <rect width=\"800\" height=\"450\" fill=\"#0b0b0c\"/>\n\
         <g fill=\"none\" stroke=\"#3a3a42\" stroke-width=\"1\">\n\
         <rect x=\"50\" y=\"190\" width=\"140\" height=\"70\"/>\n\
         <rect x=\"250\" y=\"190\" width=\"140\" height=\"70\"/>\n\
         <rect x=\"450\" y=\"190\" width=\"140\" height=\"70\"/>\n\
         <rect x=\"650\" y=\"190\" width=\"100\" height=\"70\"/>\n\
         <path d=\"M190 225 H250 M390 225 H450 M590 225 H650\"/>\n\
         </g>\n\
         <g fill=\"#c9c9cf\" font-family=\"monospace\" font-size=\"14\">\n\
         <text x=\"62\" y=\"222\">INPUT</text>\n\
         <text x=\"262\" y=\"222\">SEAL</text>\n\
         <text x=\"462\" y=\"222\">INDEX</text>\n\
         <text x=\"662\" y=\"222\">EXPORT</text>\n\
         </g>\n\
         <g fill=\"#6f6f78\" font-family=\"monospace\" font-size=\"11\">\n\
         <text x=\"62\" y=\"238\">local files</text>\n\
         <text x=\"262\" y=\"238\">AES-256-GCM</text>\n\
         <text x=\"462\" y=\"238\">encrypted</text>\n\
         <text x=\"662\" y=\"238\">verified</text>\n\
         <text x=\"50\" y=\"150\">SAMPLE DIAGRAM / FICTIONAL</text>\n\
         </g>\n\
         </svg>\n",
    )
    .into_bytes()
}

fn binary_sample() -> Vec<u8> {
    let mut data = Vec::with_capacity(24 * 1024);
    data.extend_from_slice(b"DDD FICTIONAL ARCHIVE SAMPLE\n");
    for index in 0..(24 * 1024 - data.len()) {
        data.push(((index * 37 + 11) % 251) as u8);
    }
    data
}

fn paragraph_report(title: &str, intro: &str, sections: usize) -> Vec<u8> {
    let mut text = String::new();
    text.push_str(title);
    text.push_str("\n\n");
    text.push_str(intro);
    text.push_str("\n\n");
    for index in 1..=sections {
        text.push_str(&format!("Section {index}\n"));
        text.push_str(
            "The sample text in this section is intentionally generic. It describes a \
             workflow, a decision and an open question so that the document has a natural \
             shape when previewed or exported.\n\n",
        );
    }
    text.into_bytes()
}

fn markdown_notes() -> Vec<u8> {
    let mut text = String::from("# Field notes (sample)\n\n");
    for index in 1..=12 {
        text.push_str(&format!(
            "- Observation {index}: placeholder note about item {index}, recorded during a fictional review.\n"
        ));
    }
    text.push_str("\n## Follow-up\n\n1. Confirm the sample schedule.\n2. Recheck the inventory counts.\n3. Archive the draft.\n");
    text.into_bytes()
}

fn csv_table() -> Vec<u8> {
    let mut text = String::from("item,quantity,unit_cost,note\n");
    for index in 1..=40 {
        text.push_str(&format!(
            "Sample item {index},{},{}.{:02},placeholder row\n",
            (index * 7) % 23 + 1,
            12 + index % 40,
            index % 100
        ));
    }
    text.into_bytes()
}

fn json_inventory() -> Vec<u8> {
    let mut items = Vec::new();
    for index in 1..=18 {
        items.push(format!(
            "    {{\"id\": \"sample-{index:03}\", \"label\": \"Placeholder {index}\", \"status\": \"stored\", \"revision\": {}}}",
            index * 3
        ));
    }
    format!(
        "{{\n  \"collection\": \"Sample inventory\",\n  \"fictional\": true,\n  \"items\": [\n{}\n  ]\n}}\n",
        items.join(",\n")
    )
    .into_bytes()
}

fn archive_index() -> Vec<u8> {
    let mut text = String::from("ARCHIVE INDEX - SAMPLE DOCUMENT\n\n");
    for index in 1..=60 {
        text.push_str(&format!(
            "box-{:03}  folder-{:02}  sample entry {index}\n",
            index / 4 + 1,
            index % 12 + 1
        ));
    }
    text.into_bytes()
}

fn checklist() -> Vec<u8> {
    let mut text = String::from("# Release checklist (sample)\n\n");
    for index in 1..=9 {
        text.push_str(&format!("- [x] Sample step {index} completed\n"));
    }
    text.push_str("\nThe checklist is fictional and serves only as demo content.\n");
    text.into_bytes()
}
