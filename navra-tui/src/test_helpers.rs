use ratatui::buffer::Buffer;

pub fn buf_to_string(buf: &Buffer) -> String {
    let area = buf.area;
    let mut lines = Vec::with_capacity(area.height as usize);
    for y in area.y..area.y + area.height {
        let mut line = String::with_capacity(area.width as usize);
        for x in area.x..area.x + area.width {
            let cell = &buf[(x, y)];
            line.push_str(cell.symbol());
        }
        lines.push(line.trim_end().to_string());
    }
    while lines.last().map(|l| l.is_empty()).unwrap_or(false) {
        lines.pop();
    }
    lines.join("\n")
}
