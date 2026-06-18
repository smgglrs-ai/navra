pub const UI_DIST_AVAILABLE: bool = true;

const ASSET_ASSETS_INDEX_BUOIRRDM_CSS: &[u8] = include_bytes!("../ui-dist/assets/index-BuoIrrDM.css");
const ASSET_ASSETS_INDEX_DFUB4QPN_JS: &[u8] = include_bytes!("../ui-dist/assets/index-DFUB4QPn.js");
const ASSET_INDEX_HTML: &[u8] = include_bytes!("../ui-dist/index.html");

pub fn get_asset(path: &str) -> Option<(&'static [u8], &'static str)> {
    match path {
        "/assets/index-BuoIrrDM.css" => Some((ASSET_ASSETS_INDEX_BUOIRRDM_CSS, "text/css")),
        "/assets/index-DFUB4QPn.js" => Some((ASSET_ASSETS_INDEX_DFUB4QPN_JS, "application/javascript")),
        "/index.html" => Some((ASSET_INDEX_HTML, "text/html; charset=utf-8")),
        _ => None,
    }
}

pub fn index_html() -> &'static [u8] { ASSET_INDEX_HTML }
