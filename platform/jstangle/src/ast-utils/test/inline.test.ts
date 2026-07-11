import { parse } from '@babel/parser';
import * as t from '@babel/types';
import { traverse } from '../babel';
import { expect, test } from 'vitest';
import {
  inlineArrayElements,
  inlineFunction,
  inlineObjectProperties,
  inlineVariable,
} from '..';

test('inline variable', () => {
  const ast = parse('let a = 1; let b = a;');
  traverse(ast, {
    Program(path) {
      const binding = path.scope.getBinding('a')!;
      inlineVariable(binding);
    },
  });
  expect(ast).toMatchInlineSnapshot(`
    Node {
      "comments": [],
      "end": 21,
      "errors": [],
      "loc": SourceLocation {
        "end": Position {
          "column": 21,
          "index": 21,
          "line": 1,
        },
        "filename": undefined,
        "identifierName": undefined,
        "start": Position {
          "column": 0,
          "index": 0,
          "line": 1,
        },
      },
      "program": Node {
        "body": [
          Node {
            "declarations": [
              Node {
                "end": 20,
                "id": Node {
                  "end": 16,
                  "loc": SourceLocation {
                    "end": Position {
                      "column": 16,
                      "index": 16,
                      "line": 1,
                    },
                    "filename": undefined,
                    "identifierName": "b",
                    "start": Position {
                      "column": 15,
                      "index": 15,
                      "line": 1,
                    },
                  },
                  "name": "b",
                  "start": 15,
                  "type": "Identifier",
                },
                "init": Node {
                  "end": 9,
                  "extra": {
                    "raw": "1",
                    "rawValue": 1,
                  },
                  "innerComments": [],
                  "leadingComments": [],
                  "loc": SourceLocation {
                    "end": Position {
                      "column": 9,
                      "index": 9,
                      "line": 1,
                    },
                    "filename": undefined,
                    "identifierName": undefined,
                    "start": Position {
                      "column": 8,
                      "index": 8,
                      "line": 1,
                    },
                  },
                  "start": 8,
                  "trailingComments": [],
                  "type": "NumericLiteral",
                  "value": 1,
                },
                "loc": SourceLocation {
                  "end": Position {
                    "column": 20,
                    "index": 20,
                    "line": 1,
                  },
                  "filename": undefined,
                  "identifierName": undefined,
                  "start": Position {
                    "column": 15,
                    "index": 15,
                    "line": 1,
                  },
                },
                "start": 15,
                "type": "VariableDeclarator",
              },
            ],
            "end": 21,
            "kind": "let",
            "loc": SourceLocation {
              "end": Position {
                "column": 21,
                "index": 21,
                "line": 1,
              },
              "filename": undefined,
              "identifierName": undefined,
              "start": Position {
                "column": 11,
                "index": 11,
                "line": 1,
              },
            },
            "start": 11,
            "type": "VariableDeclaration",
          },
        ],
        "directives": [],
        "end": 21,
        "interpreter": null,
        "loc": SourceLocation {
          "end": Position {
            "column": 21,
            "index": 21,
            "line": 1,
          },
          "filename": undefined,
          "identifierName": undefined,
          "start": Position {
            "column": 0,
            "index": 0,
            "line": 1,
          },
        },
        "sourceType": "script",
        "start": 0,
        "type": "Program",
      },
      "start": 0,
      "type": "File",
    }
  `);
});

test('inline variable with assignment', () => {
  const ast = parse('let a; a = 1; let b = a;');
  traverse(ast, {
    Program(path) {
      const binding = path.scope.getBinding('a')!;
      inlineVariable(binding, undefined, true);
    },
  });
  expect(ast).toMatchInlineSnapshot(`
    Node {
      "comments": [],
      "end": 24,
      "errors": [],
      "loc": SourceLocation {
        "end": Position {
          "column": 24,
          "index": 24,
          "line": 1,
        },
        "filename": undefined,
        "identifierName": undefined,
        "start": Position {
          "column": 0,
          "index": 0,
          "line": 1,
        },
      },
      "program": Node {
        "body": [
          Node {
            "declarations": [
              Node {
                "end": 23,
                "id": Node {
                  "end": 19,
                  "loc": SourceLocation {
                    "end": Position {
                      "column": 19,
                      "index": 19,
                      "line": 1,
                    },
                    "filename": undefined,
                    "identifierName": "b",
                    "start": Position {
                      "column": 18,
                      "index": 18,
                      "line": 1,
                    },
                  },
                  "name": "b",
                  "start": 18,
                  "type": "Identifier",
                },
                "init": Node {
                  "end": 12,
                  "extra": {
                    "raw": "1",
                    "rawValue": 1,
                  },
                  "innerComments": [],
                  "leadingComments": [],
                  "loc": SourceLocation {
                    "end": Position {
                      "column": 12,
                      "index": 12,
                      "line": 1,
                    },
                    "filename": undefined,
                    "identifierName": undefined,
                    "start": Position {
                      "column": 11,
                      "index": 11,
                      "line": 1,
                    },
                  },
                  "start": 11,
                  "trailingComments": [],
                  "type": "NumericLiteral",
                  "value": 1,
                },
                "loc": SourceLocation {
                  "end": Position {
                    "column": 23,
                    "index": 23,
                    "line": 1,
                  },
                  "filename": undefined,
                  "identifierName": undefined,
                  "start": Position {
                    "column": 18,
                    "index": 18,
                    "line": 1,
                  },
                },
                "start": 18,
                "type": "VariableDeclarator",
              },
            ],
            "end": 24,
            "kind": "let",
            "loc": SourceLocation {
              "end": Position {
                "column": 24,
                "index": 24,
                "line": 1,
              },
              "filename": undefined,
              "identifierName": undefined,
              "start": Position {
                "column": 14,
                "index": 14,
                "line": 1,
              },
            },
            "start": 14,
            "type": "VariableDeclaration",
          },
        ],
        "directives": [],
        "end": 24,
        "interpreter": null,
        "loc": SourceLocation {
          "end": Position {
            "column": 24,
            "index": 24,
            "line": 1,
          },
          "filename": undefined,
          "identifierName": undefined,
          "start": Position {
            "column": 0,
            "index": 0,
            "line": 1,
          },
        },
        "sourceType": "script",
        "start": 0,
        "type": "Program",
      },
      "start": 0,
      "type": "File",
    }
  `);
});

test('inline variable with multiple assignments', () => {
  const ast = parse('let a; a = 1; let b = a; a = 2; let c = a; a = 3;');
  traverse(ast, {
    Program(path) {
      const binding = path.scope.getBinding('a')!;
      inlineVariable(binding, undefined, true);
    },
  });
  expect(ast).toMatchInlineSnapshot(`
    Node {
      "comments": [],
      "end": 49,
      "errors": [],
      "loc": SourceLocation {
        "end": Position {
          "column": 49,
          "index": 49,
          "line": 1,
        },
        "filename": undefined,
        "identifierName": undefined,
        "start": Position {
          "column": 0,
          "index": 0,
          "line": 1,
        },
      },
      "program": Node {
        "body": [
          Node {
            "declarations": [
              Node {
                "end": 23,
                "id": Node {
                  "end": 19,
                  "loc": SourceLocation {
                    "end": Position {
                      "column": 19,
                      "index": 19,
                      "line": 1,
                    },
                    "filename": undefined,
                    "identifierName": "b",
                    "start": Position {
                      "column": 18,
                      "index": 18,
                      "line": 1,
                    },
                  },
                  "name": "b",
                  "start": 18,
                  "type": "Identifier",
                },
                "init": Node {
                  "end": 12,
                  "extra": {
                    "raw": "1",
                    "rawValue": 1,
                  },
                  "innerComments": [],
                  "leadingComments": [],
                  "loc": SourceLocation {
                    "end": Position {
                      "column": 12,
                      "index": 12,
                      "line": 1,
                    },
                    "filename": undefined,
                    "identifierName": undefined,
                    "start": Position {
                      "column": 11,
                      "index": 11,
                      "line": 1,
                    },
                  },
                  "start": 11,
                  "trailingComments": [],
                  "type": "NumericLiteral",
                  "value": 1,
                },
                "loc": SourceLocation {
                  "end": Position {
                    "column": 23,
                    "index": 23,
                    "line": 1,
                  },
                  "filename": undefined,
                  "identifierName": undefined,
                  "start": Position {
                    "column": 18,
                    "index": 18,
                    "line": 1,
                  },
                },
                "start": 18,
                "type": "VariableDeclarator",
              },
            ],
            "end": 24,
            "kind": "let",
            "loc": SourceLocation {
              "end": Position {
                "column": 24,
                "index": 24,
                "line": 1,
              },
              "filename": undefined,
              "identifierName": undefined,
              "start": Position {
                "column": 14,
                "index": 14,
                "line": 1,
              },
            },
            "start": 14,
            "type": "VariableDeclaration",
          },
          Node {
            "declarations": [
              Node {
                "end": 41,
                "id": Node {
                  "end": 37,
                  "loc": SourceLocation {
                    "end": Position {
                      "column": 37,
                      "index": 37,
                      "line": 1,
                    },
                    "filename": undefined,
                    "identifierName": "c",
                    "start": Position {
                      "column": 36,
                      "index": 36,
                      "line": 1,
                    },
                  },
                  "name": "c",
                  "start": 36,
                  "type": "Identifier",
                },
                "init": Node {
                  "end": 30,
                  "extra": {
                    "raw": "2",
                    "rawValue": 2,
                  },
                  "innerComments": [],
                  "leadingComments": [],
                  "loc": SourceLocation {
                    "end": Position {
                      "column": 30,
                      "index": 30,
                      "line": 1,
                    },
                    "filename": undefined,
                    "identifierName": undefined,
                    "start": Position {
                      "column": 29,
                      "index": 29,
                      "line": 1,
                    },
                  },
                  "start": 29,
                  "trailingComments": [],
                  "type": "NumericLiteral",
                  "value": 2,
                },
                "loc": SourceLocation {
                  "end": Position {
                    "column": 41,
                    "index": 41,
                    "line": 1,
                  },
                  "filename": undefined,
                  "identifierName": undefined,
                  "start": Position {
                    "column": 36,
                    "index": 36,
                    "line": 1,
                  },
                },
                "start": 36,
                "type": "VariableDeclarator",
              },
            ],
            "end": 42,
            "kind": "let",
            "loc": SourceLocation {
              "end": Position {
                "column": 42,
                "index": 42,
                "line": 1,
              },
              "filename": undefined,
              "identifierName": undefined,
              "start": Position {
                "column": 32,
                "index": 32,
                "line": 1,
              },
            },
            "start": 32,
            "type": "VariableDeclaration",
          },
        ],
        "directives": [],
        "end": 49,
        "interpreter": null,
        "loc": SourceLocation {
          "end": Position {
            "column": 49,
            "index": 49,
            "line": 1,
          },
          "filename": undefined,
          "identifierName": undefined,
          "start": Position {
            "column": 0,
            "index": 0,
            "line": 1,
          },
        },
        "sourceType": "script",
        "start": 0,
        "type": "Program",
      },
      "start": 0,
      "type": "File",
    }
  `);
});

test('inline variable with assignment in an expression', () => {
  const ast = parse('let a; x = a = 1; let b = a;');
  traverse(ast, {
    Program(path) {
      const binding = path.scope.getBinding('a')!;
      inlineVariable(binding, undefined, true);
    },
  });
  expect(ast).toMatchInlineSnapshot(`
    Node {
      "comments": [],
      "end": 28,
      "errors": [],
      "loc": SourceLocation {
        "end": Position {
          "column": 28,
          "index": 28,
          "line": 1,
        },
        "filename": undefined,
        "identifierName": undefined,
        "start": Position {
          "column": 0,
          "index": 0,
          "line": 1,
        },
      },
      "program": Node {
        "body": [
          Node {
            "end": 17,
            "expression": Node {
              "end": 16,
              "left": Node {
                "end": 8,
                "loc": SourceLocation {
                  "end": Position {
                    "column": 8,
                    "index": 8,
                    "line": 1,
                  },
                  "filename": undefined,
                  "identifierName": "x",
                  "start": Position {
                    "column": 7,
                    "index": 7,
                    "line": 1,
                  },
                },
                "name": "x",
                "start": 7,
                "type": "Identifier",
              },
              "loc": SourceLocation {
                "end": Position {
                  "column": 16,
                  "index": 16,
                  "line": 1,
                },
                "filename": undefined,
                "identifierName": undefined,
                "start": Position {
                  "column": 7,
                  "index": 7,
                  "line": 1,
                },
              },
              "operator": "=",
              "right": Node {
                "end": 16,
                "extra": {
                  "raw": "1",
                  "rawValue": 1,
                },
                "innerComments": [],
                "leadingComments": [],
                "loc": SourceLocation {
                  "end": Position {
                    "column": 16,
                    "index": 16,
                    "line": 1,
                  },
                  "filename": undefined,
                  "identifierName": undefined,
                  "start": Position {
                    "column": 15,
                    "index": 15,
                    "line": 1,
                  },
                },
                "start": 15,
                "trailingComments": [],
                "type": "NumericLiteral",
                "value": 1,
              },
              "start": 7,
              "type": "AssignmentExpression",
            },
            "loc": SourceLocation {
              "end": Position {
                "column": 17,
                "index": 17,
                "line": 1,
              },
              "filename": undefined,
              "identifierName": undefined,
              "start": Position {
                "column": 7,
                "index": 7,
                "line": 1,
              },
            },
            "start": 7,
            "type": "ExpressionStatement",
          },
          Node {
            "declarations": [
              Node {
                "end": 27,
                "id": Node {
                  "end": 23,
                  "loc": SourceLocation {
                    "end": Position {
                      "column": 23,
                      "index": 23,
                      "line": 1,
                    },
                    "filename": undefined,
                    "identifierName": "b",
                    "start": Position {
                      "column": 22,
                      "index": 22,
                      "line": 1,
                    },
                  },
                  "name": "b",
                  "start": 22,
                  "type": "Identifier",
                },
                "init": Node {
                  "end": 16,
                  "extra": {
                    "raw": "1",
                    "rawValue": 1,
                  },
                  "innerComments": [],
                  "leadingComments": [],
                  "loc": SourceLocation {
                    "end": Position {
                      "column": 16,
                      "index": 16,
                      "line": 1,
                    },
                    "filename": undefined,
                    "identifierName": undefined,
                    "start": Position {
                      "column": 15,
                      "index": 15,
                      "line": 1,
                    },
                  },
                  "start": 15,
                  "trailingComments": [],
                  "type": "NumericLiteral",
                  "value": 1,
                },
                "loc": SourceLocation {
                  "end": Position {
                    "column": 27,
                    "index": 27,
                    "line": 1,
                  },
                  "filename": undefined,
                  "identifierName": undefined,
                  "start": Position {
                    "column": 22,
                    "index": 22,
                    "line": 1,
                  },
                },
                "start": 22,
                "type": "VariableDeclarator",
              },
            ],
            "end": 28,
            "kind": "let",
            "loc": SourceLocation {
              "end": Position {
                "column": 28,
                "index": 28,
                "line": 1,
              },
              "filename": undefined,
              "identifierName": undefined,
              "start": Position {
                "column": 18,
                "index": 18,
                "line": 1,
              },
            },
            "start": 18,
            "type": "VariableDeclaration",
          },
        ],
        "directives": [],
        "end": 28,
        "interpreter": null,
        "loc": SourceLocation {
          "end": Position {
            "column": 28,
            "index": 28,
            "line": 1,
          },
          "filename": undefined,
          "identifierName": undefined,
          "start": Position {
            "column": 0,
            "index": 0,
            "line": 1,
          },
        },
        "sourceType": "script",
        "start": 0,
        "type": "Program",
      },
      "start": 0,
      "type": "File",
    }
  `);
});

test('inline array elements', () => {
  const ast = parse('const arr = ["foo", "bar"]; console.log(arr[0]);');
  traverse(ast, {
    ArrayExpression(path) {
      const binding = path.scope.getBinding('arr')!;
      inlineArrayElements(path.node, binding.referencePaths);
    },
  });
  expect(ast).toMatchInlineSnapshot(`
    Node {
      "comments": [],
      "end": 48,
      "errors": [],
      "loc": SourceLocation {
        "end": Position {
          "column": 48,
          "index": 48,
          "line": 1,
        },
        "filename": undefined,
        "identifierName": undefined,
        "start": Position {
          "column": 0,
          "index": 0,
          "line": 1,
        },
      },
      "program": Node {
        "body": [
          Node {
            "declarations": [
              Node {
                "end": 26,
                "id": Node {
                  "end": 9,
                  "loc": SourceLocation {
                    "end": Position {
                      "column": 9,
                      "index": 9,
                      "line": 1,
                    },
                    "filename": undefined,
                    "identifierName": "arr",
                    "start": Position {
                      "column": 6,
                      "index": 6,
                      "line": 1,
                    },
                  },
                  "name": "arr",
                  "start": 6,
                  "type": "Identifier",
                },
                "init": Node {
                  "elements": [
                    Node {
                      "end": 18,
                      "extra": {
                        "raw": ""foo"",
                        "rawValue": "foo",
                      },
                      "loc": SourceLocation {
                        "end": Position {
                          "column": 18,
                          "index": 18,
                          "line": 1,
                        },
                        "filename": undefined,
                        "identifierName": undefined,
                        "start": Position {
                          "column": 13,
                          "index": 13,
                          "line": 1,
                        },
                      },
                      "start": 13,
                      "type": "StringLiteral",
                      "value": "foo",
                    },
                    Node {
                      "end": 25,
                      "extra": {
                        "raw": ""bar"",
                        "rawValue": "bar",
                      },
                      "loc": SourceLocation {
                        "end": Position {
                          "column": 25,
                          "index": 25,
                          "line": 1,
                        },
                        "filename": undefined,
                        "identifierName": undefined,
                        "start": Position {
                          "column": 20,
                          "index": 20,
                          "line": 1,
                        },
                      },
                      "start": 20,
                      "type": "StringLiteral",
                      "value": "bar",
                    },
                  ],
                  "end": 26,
                  "loc": SourceLocation {
                    "end": Position {
                      "column": 26,
                      "index": 26,
                      "line": 1,
                    },
                    "filename": undefined,
                    "identifierName": undefined,
                    "start": Position {
                      "column": 12,
                      "index": 12,
                      "line": 1,
                    },
                  },
                  "start": 12,
                  "type": "ArrayExpression",
                },
                "loc": SourceLocation {
                  "end": Position {
                    "column": 26,
                    "index": 26,
                    "line": 1,
                  },
                  "filename": undefined,
                  "identifierName": undefined,
                  "start": Position {
                    "column": 6,
                    "index": 6,
                    "line": 1,
                  },
                },
                "start": 6,
                "type": "VariableDeclarator",
              },
            ],
            "end": 27,
            "kind": "const",
            "loc": SourceLocation {
              "end": Position {
                "column": 27,
                "index": 27,
                "line": 1,
              },
              "filename": undefined,
              "identifierName": undefined,
              "start": Position {
                "column": 0,
                "index": 0,
                "line": 1,
              },
            },
            "start": 0,
            "type": "VariableDeclaration",
          },
          Node {
            "end": 48,
            "expression": Node {
              "arguments": [
                {
                  "extra": {
                    "raw": ""foo"",
                    "rawValue": "foo",
                  },
                  "innerComments": [],
                  "leadingComments": [],
                  "loc": SourceLocation {
                    "end": Position {
                      "column": 18,
                      "index": 18,
                      "line": 1,
                    },
                    "filename": undefined,
                    "identifierName": undefined,
                    "start": Position {
                      "column": 13,
                      "index": 13,
                      "line": 1,
                    },
                  },
                  "trailingComments": [],
                  "type": "StringLiteral",
                  "value": "foo",
                },
              ],
              "callee": Node {
                "computed": false,
                "end": 39,
                "loc": SourceLocation {
                  "end": Position {
                    "column": 39,
                    "index": 39,
                    "line": 1,
                  },
                  "filename": undefined,
                  "identifierName": undefined,
                  "start": Position {
                    "column": 28,
                    "index": 28,
                    "line": 1,
                  },
                },
                "object": Node {
                  "end": 35,
                  "loc": SourceLocation {
                    "end": Position {
                      "column": 35,
                      "index": 35,
                      "line": 1,
                    },
                    "filename": undefined,
                    "identifierName": "console",
                    "start": Position {
                      "column": 28,
                      "index": 28,
                      "line": 1,
                    },
                  },
                  "name": "console",
                  "start": 28,
                  "type": "Identifier",
                },
                "property": Node {
                  "end": 39,
                  "loc": SourceLocation {
                    "end": Position {
                      "column": 39,
                      "index": 39,
                      "line": 1,
                    },
                    "filename": undefined,
                    "identifierName": "log",
                    "start": Position {
                      "column": 36,
                      "index": 36,
                      "line": 1,
                    },
                  },
                  "name": "log",
                  "start": 36,
                  "type": "Identifier",
                },
                "start": 28,
                "type": "MemberExpression",
              },
              "end": 47,
              "loc": SourceLocation {
                "end": Position {
                  "column": 47,
                  "index": 47,
                  "line": 1,
                },
                "filename": undefined,
                "identifierName": undefined,
                "start": Position {
                  "column": 28,
                  "index": 28,
                  "line": 1,
                },
              },
              "start": 28,
              "type": "CallExpression",
            },
            "loc": SourceLocation {
              "end": Position {
                "column": 48,
                "index": 48,
                "line": 1,
              },
              "filename": undefined,
              "identifierName": undefined,
              "start": Position {
                "column": 28,
                "index": 28,
                "line": 1,
              },
            },
            "start": 28,
            "type": "ExpressionStatement",
          },
        ],
        "directives": [],
        "end": 48,
        "interpreter": null,
        "loc": SourceLocation {
          "end": Position {
            "column": 48,
            "index": 48,
            "line": 1,
          },
          "filename": undefined,
          "identifierName": undefined,
          "start": Position {
            "column": 0,
            "index": 0,
            "line": 1,
          },
        },
        "sourceType": "script",
        "start": 0,
        "type": "Program",
      },
      "start": 0,
      "type": "File",
    }
  `);
});

test('inline object properties', () => {
  const ast = parse(`
    const obj = { c: 0x2f2, d: '0x396' };
    console.log(obj.c, obj.d);
  `);
  traverse(ast, {
    Program(path) {
      const binding = path.scope.getBinding('obj')!;
      inlineObjectProperties(binding);
    },
  });
  expect(ast).toMatchInlineSnapshot(`
    Node {
      "comments": [],
      "end": 76,
      "errors": [],
      "loc": SourceLocation {
        "end": Position {
          "column": 2,
          "index": 76,
          "line": 4,
        },
        "filename": undefined,
        "identifierName": undefined,
        "start": Position {
          "column": 0,
          "index": 0,
          "line": 1,
        },
      },
      "program": Node {
        "body": [
          Node {
            "end": 73,
            "expression": Node {
              "arguments": [
                Node {
                  "end": 27,
                  "extra": {
                    "raw": "0x2f2",
                    "rawValue": 754,
                  },
                  "innerComments": [],
                  "leadingComments": [],
                  "loc": SourceLocation {
                    "end": Position {
                      "column": 26,
                      "index": 27,
                      "line": 2,
                    },
                    "filename": undefined,
                    "identifierName": undefined,
                    "start": Position {
                      "column": 21,
                      "index": 22,
                      "line": 2,
                    },
                  },
                  "start": 22,
                  "trailingComments": [],
                  "type": "NumericLiteral",
                  "value": 754,
                },
                Node {
                  "end": 39,
                  "extra": {
                    "raw": "'0x396'",
                    "rawValue": "0x396",
                  },
                  "innerComments": [],
                  "leadingComments": [],
                  "loc": SourceLocation {
                    "end": Position {
                      "column": 38,
                      "index": 39,
                      "line": 2,
                    },
                    "filename": undefined,
                    "identifierName": undefined,
                    "start": Position {
                      "column": 31,
                      "index": 32,
                      "line": 2,
                    },
                  },
                  "start": 32,
                  "trailingComments": [],
                  "type": "StringLiteral",
                  "value": "0x396",
                },
              ],
              "callee": Node {
                "computed": false,
                "end": 58,
                "loc": SourceLocation {
                  "end": Position {
                    "column": 15,
                    "index": 58,
                    "line": 3,
                  },
                  "filename": undefined,
                  "identifierName": undefined,
                  "start": Position {
                    "column": 4,
                    "index": 47,
                    "line": 3,
                  },
                },
                "object": Node {
                  "end": 54,
                  "loc": SourceLocation {
                    "end": Position {
                      "column": 11,
                      "index": 54,
                      "line": 3,
                    },
                    "filename": undefined,
                    "identifierName": "console",
                    "start": Position {
                      "column": 4,
                      "index": 47,
                      "line": 3,
                    },
                  },
                  "name": "console",
                  "start": 47,
                  "type": "Identifier",
                },
                "property": Node {
                  "end": 58,
                  "loc": SourceLocation {
                    "end": Position {
                      "column": 15,
                      "index": 58,
                      "line": 3,
                    },
                    "filename": undefined,
                    "identifierName": "log",
                    "start": Position {
                      "column": 12,
                      "index": 55,
                      "line": 3,
                    },
                  },
                  "name": "log",
                  "start": 55,
                  "type": "Identifier",
                },
                "start": 47,
                "type": "MemberExpression",
              },
              "end": 72,
              "loc": SourceLocation {
                "end": Position {
                  "column": 29,
                  "index": 72,
                  "line": 3,
                },
                "filename": undefined,
                "identifierName": undefined,
                "start": Position {
                  "column": 4,
                  "index": 47,
                  "line": 3,
                },
              },
              "start": 47,
              "type": "CallExpression",
            },
            "loc": SourceLocation {
              "end": Position {
                "column": 30,
                "index": 73,
                "line": 3,
              },
              "filename": undefined,
              "identifierName": undefined,
              "start": Position {
                "column": 4,
                "index": 47,
                "line": 3,
              },
            },
            "start": 47,
            "type": "ExpressionStatement",
          },
        ],
        "directives": [],
        "end": 76,
        "interpreter": null,
        "loc": SourceLocation {
          "end": Position {
            "column": 2,
            "index": 76,
            "line": 4,
          },
          "filename": undefined,
          "identifierName": undefined,
          "start": Position {
            "column": 0,
            "index": 0,
            "line": 1,
          },
        },
        "sourceType": "script",
        "start": 0,
        "type": "Program",
      },
      "start": 0,
      "type": "File",
    }
  `);
});

test('inline function', () => {
  const ast = parse(`
    function f(a, b) {
      return a + b;
    }
    fn(1, 2);
  `);
  traverse(ast, {
    CallExpression(path) {
      const fn = path.parentPath.getPrevSibling().node as t.FunctionDeclaration;
      inlineFunction(fn, path);
    },
  });
  expect(ast).toMatchInlineSnapshot(`
    Node {
      "comments": [],
      "end": 66,
      "errors": [],
      "loc": SourceLocation {
        "end": Position {
          "column": 2,
          "index": 66,
          "line": 6,
        },
        "filename": undefined,
        "identifierName": undefined,
        "start": Position {
          "column": 0,
          "index": 0,
          "line": 1,
        },
      },
      "program": Node {
        "body": [
          Node {
            "async": false,
            "body": Node {
              "body": [
                Node {
                  "argument": Node {
                    "end": 42,
                    "left": Node {
                      "end": 38,
                      "loc": SourceLocation {
                        "end": Position {
                          "column": 14,
                          "index": 38,
                          "line": 3,
                        },
                        "filename": undefined,
                        "identifierName": "a",
                        "start": Position {
                          "column": 13,
                          "index": 37,
                          "line": 3,
                        },
                      },
                      "name": "a",
                      "start": 37,
                      "type": "Identifier",
                    },
                    "loc": SourceLocation {
                      "end": Position {
                        "column": 18,
                        "index": 42,
                        "line": 3,
                      },
                      "filename": undefined,
                      "identifierName": undefined,
                      "start": Position {
                        "column": 13,
                        "index": 37,
                        "line": 3,
                      },
                    },
                    "operator": "+",
                    "right": Node {
                      "end": 42,
                      "loc": SourceLocation {
                        "end": Position {
                          "column": 18,
                          "index": 42,
                          "line": 3,
                        },
                        "filename": undefined,
                        "identifierName": "b",
                        "start": Position {
                          "column": 17,
                          "index": 41,
                          "line": 3,
                        },
                      },
                      "name": "b",
                      "start": 41,
                      "type": "Identifier",
                    },
                    "start": 37,
                    "type": "BinaryExpression",
                  },
                  "end": 43,
                  "loc": SourceLocation {
                    "end": Position {
                      "column": 19,
                      "index": 43,
                      "line": 3,
                    },
                    "filename": undefined,
                    "identifierName": undefined,
                    "start": Position {
                      "column": 6,
                      "index": 30,
                      "line": 3,
                    },
                  },
                  "start": 30,
                  "type": "ReturnStatement",
                },
              ],
              "directives": [],
              "end": 49,
              "loc": SourceLocation {
                "end": Position {
                  "column": 5,
                  "index": 49,
                  "line": 4,
                },
                "filename": undefined,
                "identifierName": undefined,
                "start": Position {
                  "column": 21,
                  "index": 22,
                  "line": 2,
                },
              },
              "start": 22,
              "type": "BlockStatement",
            },
            "end": 49,
            "generator": false,
            "id": Node {
              "end": 15,
              "loc": SourceLocation {
                "end": Position {
                  "column": 14,
                  "index": 15,
                  "line": 2,
                },
                "filename": undefined,
                "identifierName": "f",
                "start": Position {
                  "column": 13,
                  "index": 14,
                  "line": 2,
                },
              },
              "name": "f",
              "start": 14,
              "type": "Identifier",
            },
            "loc": SourceLocation {
              "end": Position {
                "column": 5,
                "index": 49,
                "line": 4,
              },
              "filename": undefined,
              "identifierName": undefined,
              "start": Position {
                "column": 4,
                "index": 5,
                "line": 2,
              },
            },
            "params": [
              Node {
                "end": 17,
                "loc": SourceLocation {
                  "end": Position {
                    "column": 16,
                    "index": 17,
                    "line": 2,
                  },
                  "filename": undefined,
                  "identifierName": "a",
                  "start": Position {
                    "column": 15,
                    "index": 16,
                    "line": 2,
                  },
                },
                "name": "a",
                "start": 16,
                "type": "Identifier",
              },
              Node {
                "end": 20,
                "loc": SourceLocation {
                  "end": Position {
                    "column": 19,
                    "index": 20,
                    "line": 2,
                  },
                  "filename": undefined,
                  "identifierName": "b",
                  "start": Position {
                    "column": 18,
                    "index": 19,
                    "line": 2,
                  },
                },
                "name": "b",
                "start": 19,
                "type": "Identifier",
              },
            ],
            "start": 5,
            "type": "FunctionDeclaration",
          },
          Node {
            "end": 63,
            "expression": {
              "innerComments": [],
              "leadingComments": [],
              "left": Node {
                "end": 58,
                "extra": {
                  "raw": "1",
                  "rawValue": 1,
                },
                "innerComments": [],
                "leadingComments": [],
                "loc": SourceLocation {
                  "end": Position {
                    "column": 8,
                    "index": 58,
                    "line": 5,
                  },
                  "filename": undefined,
                  "identifierName": undefined,
                  "start": Position {
                    "column": 7,
                    "index": 57,
                    "line": 5,
                  },
                },
                "start": 57,
                "trailingComments": [],
                "type": "NumericLiteral",
                "value": 1,
              },
              "loc": SourceLocation {
                "end": Position {
                  "column": 18,
                  "index": 42,
                  "line": 3,
                },
                "filename": undefined,
                "identifierName": undefined,
                "start": Position {
                  "column": 13,
                  "index": 37,
                  "line": 3,
                },
              },
              "operator": "+",
              "right": Node {
                "end": 61,
                "extra": {
                  "raw": "2",
                  "rawValue": 2,
                },
                "innerComments": [],
                "leadingComments": [],
                "loc": SourceLocation {
                  "end": Position {
                    "column": 11,
                    "index": 61,
                    "line": 5,
                  },
                  "filename": undefined,
                  "identifierName": undefined,
                  "start": Position {
                    "column": 10,
                    "index": 60,
                    "line": 5,
                  },
                },
                "start": 60,
                "trailingComments": [],
                "type": "NumericLiteral",
                "value": 2,
              },
              "trailingComments": [],
              "type": "BinaryExpression",
            },
            "loc": SourceLocation {
              "end": Position {
                "column": 13,
                "index": 63,
                "line": 5,
              },
              "filename": undefined,
              "identifierName": undefined,
              "start": Position {
                "column": 4,
                "index": 54,
                "line": 5,
              },
            },
            "start": 54,
            "type": "ExpressionStatement",
          },
        ],
        "directives": [],
        "end": 66,
        "interpreter": null,
        "loc": SourceLocation {
          "end": Position {
            "column": 2,
            "index": 66,
            "line": 6,
          },
          "filename": undefined,
          "identifierName": undefined,
          "start": Position {
            "column": 0,
            "index": 0,
            "line": 1,
          },
        },
        "sourceType": "script",
        "start": 0,
        "type": "Program",
      },
      "start": 0,
      "type": "File",
    }
  `);
});

test('inline function with rest arg', () => {
  const ast = parse(`
    function f(a, ...b) {
      return a(...b);
    }
    fn(x, 1, 2, 3);
  `);
  traverse(ast, {
    CallExpression(path) {
      if (t.isIdentifier(path.node.callee, { name: 'fn' })) {
        const fn = path.parentPath.getPrevSibling()
          .node as t.FunctionDeclaration;
        inlineFunction(fn, path);
      }
    },
  });
  expect(ast).toMatchInlineSnapshot(`
    Node {
      "comments": [],
      "end": 77,
      "errors": [],
      "loc": SourceLocation {
        "end": Position {
          "column": 2,
          "index": 77,
          "line": 6,
        },
        "filename": undefined,
        "identifierName": undefined,
        "start": Position {
          "column": 0,
          "index": 0,
          "line": 1,
        },
      },
      "program": Node {
        "body": [
          Node {
            "async": false,
            "body": Node {
              "body": [
                Node {
                  "argument": Node {
                    "arguments": [
                      Node {
                        "argument": Node {
                          "end": 46,
                          "loc": SourceLocation {
                            "end": Position {
                              "column": 19,
                              "index": 46,
                              "line": 3,
                            },
                            "filename": undefined,
                            "identifierName": "b",
                            "start": Position {
                              "column": 18,
                              "index": 45,
                              "line": 3,
                            },
                          },
                          "name": "b",
                          "start": 45,
                          "type": "Identifier",
                        },
                        "end": 46,
                        "loc": SourceLocation {
                          "end": Position {
                            "column": 19,
                            "index": 46,
                            "line": 3,
                          },
                          "filename": undefined,
                          "identifierName": undefined,
                          "start": Position {
                            "column": 15,
                            "index": 42,
                            "line": 3,
                          },
                        },
                        "start": 42,
                        "type": "SpreadElement",
                      },
                    ],
                    "callee": Node {
                      "end": 41,
                      "loc": SourceLocation {
                        "end": Position {
                          "column": 14,
                          "index": 41,
                          "line": 3,
                        },
                        "filename": undefined,
                        "identifierName": "a",
                        "start": Position {
                          "column": 13,
                          "index": 40,
                          "line": 3,
                        },
                      },
                      "name": "a",
                      "start": 40,
                      "type": "Identifier",
                    },
                    "end": 47,
                    "loc": SourceLocation {
                      "end": Position {
                        "column": 20,
                        "index": 47,
                        "line": 3,
                      },
                      "filename": undefined,
                      "identifierName": undefined,
                      "start": Position {
                        "column": 13,
                        "index": 40,
                        "line": 3,
                      },
                    },
                    "start": 40,
                    "type": "CallExpression",
                  },
                  "end": 48,
                  "loc": SourceLocation {
                    "end": Position {
                      "column": 21,
                      "index": 48,
                      "line": 3,
                    },
                    "filename": undefined,
                    "identifierName": undefined,
                    "start": Position {
                      "column": 6,
                      "index": 33,
                      "line": 3,
                    },
                  },
                  "start": 33,
                  "type": "ReturnStatement",
                },
              ],
              "directives": [],
              "end": 54,
              "loc": SourceLocation {
                "end": Position {
                  "column": 5,
                  "index": 54,
                  "line": 4,
                },
                "filename": undefined,
                "identifierName": undefined,
                "start": Position {
                  "column": 24,
                  "index": 25,
                  "line": 2,
                },
              },
              "start": 25,
              "type": "BlockStatement",
            },
            "end": 54,
            "generator": false,
            "id": Node {
              "end": 15,
              "loc": SourceLocation {
                "end": Position {
                  "column": 14,
                  "index": 15,
                  "line": 2,
                },
                "filename": undefined,
                "identifierName": "f",
                "start": Position {
                  "column": 13,
                  "index": 14,
                  "line": 2,
                },
              },
              "name": "f",
              "start": 14,
              "type": "Identifier",
            },
            "loc": SourceLocation {
              "end": Position {
                "column": 5,
                "index": 54,
                "line": 4,
              },
              "filename": undefined,
              "identifierName": undefined,
              "start": Position {
                "column": 4,
                "index": 5,
                "line": 2,
              },
            },
            "params": [
              Node {
                "end": 17,
                "loc": SourceLocation {
                  "end": Position {
                    "column": 16,
                    "index": 17,
                    "line": 2,
                  },
                  "filename": undefined,
                  "identifierName": "a",
                  "start": Position {
                    "column": 15,
                    "index": 16,
                    "line": 2,
                  },
                },
                "name": "a",
                "start": 16,
                "type": "Identifier",
              },
              Node {
                "argument": Node {
                  "end": 23,
                  "loc": SourceLocation {
                    "end": Position {
                      "column": 22,
                      "index": 23,
                      "line": 2,
                    },
                    "filename": undefined,
                    "identifierName": "b",
                    "start": Position {
                      "column": 21,
                      "index": 22,
                      "line": 2,
                    },
                  },
                  "name": "b",
                  "start": 22,
                  "type": "Identifier",
                },
                "end": 23,
                "loc": SourceLocation {
                  "end": Position {
                    "column": 22,
                    "index": 23,
                    "line": 2,
                  },
                  "filename": undefined,
                  "identifierName": undefined,
                  "start": Position {
                    "column": 18,
                    "index": 19,
                    "line": 2,
                  },
                },
                "start": 19,
                "type": "RestElement",
              },
            ],
            "start": 5,
            "type": "FunctionDeclaration",
          },
          Node {
            "end": 74,
            "expression": {
              "arguments": [
                Node {
                  "end": 66,
                  "extra": {
                    "raw": "1",
                    "rawValue": 1,
                  },
                  "loc": SourceLocation {
                    "end": Position {
                      "column": 11,
                      "index": 66,
                      "line": 5,
                    },
                    "filename": undefined,
                    "identifierName": undefined,
                    "start": Position {
                      "column": 10,
                      "index": 65,
                      "line": 5,
                    },
                  },
                  "start": 65,
                  "type": "NumericLiteral",
                  "value": 1,
                },
                Node {
                  "end": 69,
                  "extra": {
                    "raw": "2",
                    "rawValue": 2,
                  },
                  "loc": SourceLocation {
                    "end": Position {
                      "column": 14,
                      "index": 69,
                      "line": 5,
                    },
                    "filename": undefined,
                    "identifierName": undefined,
                    "start": Position {
                      "column": 13,
                      "index": 68,
                      "line": 5,
                    },
                  },
                  "start": 68,
                  "type": "NumericLiteral",
                  "value": 2,
                },
                Node {
                  "end": 72,
                  "extra": {
                    "raw": "3",
                    "rawValue": 3,
                  },
                  "loc": SourceLocation {
                    "end": Position {
                      "column": 17,
                      "index": 72,
                      "line": 5,
                    },
                    "filename": undefined,
                    "identifierName": undefined,
                    "start": Position {
                      "column": 16,
                      "index": 71,
                      "line": 5,
                    },
                  },
                  "start": 71,
                  "type": "NumericLiteral",
                  "value": 3,
                },
              ],
              "callee": Node {
                "end": 63,
                "loc": SourceLocation {
                  "end": Position {
                    "column": 8,
                    "index": 63,
                    "line": 5,
                  },
                  "filename": undefined,
                  "identifierName": "x",
                  "start": Position {
                    "column": 7,
                    "index": 62,
                    "line": 5,
                  },
                },
                "name": "x",
                "start": 62,
                "type": "Identifier",
              },
              "innerComments": [],
              "leadingComments": [],
              "trailingComments": [],
              "type": "CallExpression",
            },
            "loc": SourceLocation {
              "end": Position {
                "column": 19,
                "index": 74,
                "line": 5,
              },
              "filename": undefined,
              "identifierName": undefined,
              "start": Position {
                "column": 4,
                "index": 59,
                "line": 5,
              },
            },
            "start": 59,
            "type": "ExpressionStatement",
          },
        ],
        "directives": [],
        "end": 77,
        "interpreter": null,
        "loc": SourceLocation {
          "end": Position {
            "column": 2,
            "index": 77,
            "line": 6,
          },
          "filename": undefined,
          "identifierName": undefined,
          "start": Position {
            "column": 0,
            "index": 0,
            "line": 1,
          },
        },
        "sourceType": "script",
        "start": 0,
        "type": "Program",
      },
      "start": 0,
      "type": "File",
    }
  `);
});
