import sys
import os
from typing import List
from tree_sitter import Language, Parser


def read_file(file_path: str) -> str:
    """Đọc nội dung file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        print(f"Lỗi khi đọc file: {e}")
        return ""


def init_tree_sitter() -> Parser:
    """Khởi tạo tree-sitter parser cho Javascript."""
    try:
        Language.build_library("build/my-languages.so", ["tree-sitter-javascript"])
        JS_LANGUAGE = Language("build/my-languages.so", "javascript")
        parser = Parser()
        parser.set_language(JS_LANGUAGE)
        return parser
    except Exception as e:
        print(f"Lỗi khi khởi tạo tree-sitter: {e}")
        return None


def search_with_query(parser: Parser, content: str, query_str: str) -> List[str]:
    """Tìm kiếm trong code JS sử dụng tree-sitter query."""
    try:
        tree = parser.parse(bytes(content, "utf8"))
        query = parser.language.query(query_str)
        matches = query.matches(tree.root_node)

        results = []
        for match in matches:
            # match là một tuple (pattern_index, captures)
            pattern_index, captures = match
            for capture_index, node in enumerate(captures):
                start_point = node.start_point
                line_content = content.split("\n")[start_point[0]]
                capture_name = query.capture_names[capture_index]
                results.append(
                    f"Dòng {start_point[0] + 1} ({capture_name}): {line_content.strip()}"
                )
                # Debug info
                print(f"Node type: {node.type}")
                print(f"Node text: {node.text.decode('utf-8')}")
        return results
    except Exception as e:
        print(f"Lỗi khi thực hiện query: {e}")
        print(f"Query content:\n{query_str}")  # In ra nội dung query để debug
        return []


def main():
    if len(sys.argv) != 2:
        print("Sử dụng: python query.py <đường_dẫn_file_js>")
        sys.exit(1)

    js_file = sys.argv[1]
    query_file = "query.txt"

    if not os.path.exists(js_file):
        print(f"File Javascript không tồn tại: {js_file}")
        sys.exit(1)

    if not os.path.exists(query_file):
        print(f"File query không tồn tại: {query_file}")
        sys.exit(1)

    js_content = read_file(js_file)
    query_content = read_file(query_file)

    if not js_content or not query_content:
        sys.exit(1)

    parser = init_tree_sitter()
    if not parser:
        sys.exit(1)

    results = search_with_query(parser, js_content, query_content)

    if results:
        print("\nKết quả tìm kiếm:")
        for result in results:
            print(result)
    else:
        print("\nKhông tìm thấy kết quả nào")


if __name__ == "__main__":
    main()
