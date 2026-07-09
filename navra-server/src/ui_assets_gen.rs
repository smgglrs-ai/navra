pub const UI_DIST_AVAILABLE: bool = true;

const ASSET_ASSETS_INDEX_B9X186DI_CSS: &[u8] =
    include_bytes!("../ui-dist/assets/index-B9x186dI.css");
const ASSET_ASSETS_INDEX_DBHN8_SZ_JS: &[u8] = include_bytes!("../ui-dist/assets/index-DbhN8_SZ.js");
const ASSET_INDEX_HTML: &[u8] = include_bytes!("../ui-dist/index.html");

pub fn get_asset(path: &str) -> Option<(&'static [u8], &'static str)> {
    match path {
        "/assets/index-B9x186dI.css" => Some((ASSET_ASSETS_INDEX_B9X186DI_CSS, "text/css")),
        "/assets/index-DbhN8_SZ.js" => {
            Some((ASSET_ASSETS_INDEX_DBHN8_SZ_JS, "application/javascript"))
        }
        "/index.html" => Some((ASSET_INDEX_HTML, "text/html; charset=utf-8")),
        _ => None,
    }
}

pub fn index_html() -> &'static [u8] {
    ASSET_INDEX_HTML
}
