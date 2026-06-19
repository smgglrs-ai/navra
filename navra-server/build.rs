use std::path::Path;

fn main() {
    let ui_dist = Path::new("ui-dist");
    println!("cargo:rerun-if-changed=ui-dist");

    let out_path = Path::new("src").join("ui_assets_gen.rs");

    if !ui_dist.exists() || !ui_dist.is_dir() {
        std::fs::write(
            &out_path,
            "pub const UI_DIST_AVAILABLE: bool = false;\n\
             pub fn get_asset(_path: &str) -> Option<(&'static [u8], &'static str)> { None }\n\
             pub fn index_html() -> &'static [u8] { b\"\" }\n",
        )
        .unwrap();
        return;
    }

    let mut entries: Vec<(String, String, String)> = Vec::new();
    collect_files(ui_dist, ui_dist, &mut entries);
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut code = String::new();
    code.push_str("pub const UI_DIST_AVAILABLE: bool = true;\n\n");

    for (rel_path, abs_path, mime) in &entries {
        let const_name = path_to_const(rel_path);
        code.push_str(&format!(
            "const {const_name}: &[u8] = include_bytes!(\"../{abs_path}\");\n"
        ));
        let _ = (mime,);
    }
    code.push('\n');

    code.push_str("pub fn get_asset(path: &str) -> Option<(&'static [u8], &'static str)> {\n");
    code.push_str("    match path {\n");
    for (rel_path, _, mime) in &entries {
        let const_name = path_to_const(rel_path);
        code.push_str(&format!(
            "        \"/{rel_path}\" => Some(({const_name}, \"{mime}\")),\n"
        ));
    }
    code.push_str("        _ => None,\n");
    code.push_str("    }\n");
    code.push_str("}\n\n");

    let index_const = entries
        .iter()
        .find(|(p, _, _)| p == "index.html")
        .map(|(_, _, _)| path_to_const("index.html"))
        .unwrap_or_else(|| "b\"\"".to_string());
    code.push_str(&format!(
        "pub fn index_html() -> &'static [u8] {{ {index_const} }}\n"
    ));

    std::fs::write(&out_path, code).unwrap();
}

fn collect_files(dir: &Path, root: &Path, entries: &mut Vec<(String, String, String)>) {
    let Ok(read_dir) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, root, entries);
        } else {
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let abs = format!("ui-dist/{rel}");
            let mime = guess_mime(&rel);
            entries.push((rel, abs, mime));
        }
    }
}

fn guess_mime(path: &str) -> String {
    if path.ends_with(".html") {
        "text/html; charset=utf-8".into()
    } else if path.ends_with(".css") {
        "text/css".into()
    } else if path.ends_with(".js") {
        "application/javascript".into()
    } else if path.ends_with(".json") {
        "application/json".into()
    } else if path.ends_with(".svg") {
        "image/svg+xml".into()
    } else if path.ends_with(".png") {
        "image/png".into()
    } else if path.ends_with(".woff2") {
        "font/woff2".into()
    } else if path.ends_with(".woff") {
        "font/woff".into()
    } else {
        "application/octet-stream".into()
    }
}

fn path_to_const(path: &str) -> String {
    let name = path.replace(['/', '.', '-'], "_").to_uppercase();
    format!("ASSET_{name}")
}
