from pathlib import Path
from typing import Sequence
from rich.progress import ProgressColumn, Task
from rich.text import Text


class FileColumn(ProgressColumn):
    def __init__(self, seq: Sequence[str], root_path: str = "") -> None:
        self._seq = seq
        self._count = len(seq)
        self.root_path = root_path
        super().__init__()

    def render(self, task: Task) -> Text:
        filename = self._seq[int(task.completed) - 1]
        if self.root_path and filename.startswith(self.root_path):
            filename = filename[len(self.root_path) + 1 :]

        _text: str = filename if task.completed < (self._count - 1) else ""
        if _text:
            p = Path(_text)
            _text = p.name
            parts = p.parts
            if len(parts) > 3:
                prefix = str(parts[0])
                suffix = "/".join(parts[-2:])
                _text = f"{prefix}/.../{suffix}"
            else:
                _text = str(p)
        text = Text(_text)
        return text
