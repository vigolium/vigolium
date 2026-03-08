import { parse } from '@babel/parser';
import * as t from '@babel/types';
import debug from 'debug';
import { traverse } from '../ast-utils/babel';

const log = debug('jsscan:identifierCollector');

/**
 * Thu thập tất cả các identifier được sử dụng làm tham số/biến trong code.
 * Hàm này sẽ phân tích code và trích xuất các identifier trong ngữ cảnh sử dụng, không phải khai báo.
 * 
 * @example
 * ```typescript
 * // Input code
 * const code = `
 *   // Những identifier này sẽ KHÔNG được thu thập vì là nơi khai báo
 *   const config = {
 *     auth: {
 *       API_KEY: 'xxx'
 *     }
 *   };
 * 
 *   // Những identifier này SẼ được thu thập vì đang được sử dụng
 *   fetch(API_URL);
 *   headers['Authorization'] = config.auth.API_KEY;
 *   client.request(token);
 * `;
 * 
 * const identifiers = collectIdentifiers(code);
 * console.log([...identifiers]);
 * // Output: ['API_URL', 'API_KEY', 'token']
 * ```
 * 
 * @param code - Đoạn code JavaScript/TypeScript cần phân tích
 * @returns Set<string> - Tập hợp các identifier duy nhất được tìm thấy
 * 
 * @remarks
 * - Chỉ thu thập identifier trong ngữ cảnh sử dụng (ví dụ: tham số hàm, biến trong biểu thức)
 * - Bỏ qua các identifier trong ngữ cảnh khai báo (ví dụ: khai báo object, khai báo biến)
 * - Nếu code không thể parse được, hàm sẽ trả về Set rỗng và log lỗi
 */
export function collectIdentifiers(code: string): Set<string> {
    const identifiers = new Set<string>();
    if (code == null || code == '' || code.length === 0) {
        return identifiers;
    }

    try {
        // Tiền xử lý code để handle các trường hợp function declarations
        let codeToProcess = code.trim();

        // Case 1: Anonymous functions
        if (codeToProcess.startsWith('function(')) {
            codeToProcess = `const anonymousFunc = ${codeToProcess}`;
        }

        // Case 2: Arrow functions
        else if (codeToProcess.startsWith('(') && codeToProcess.includes('=>')) {
            codeToProcess = `const arrowFunc = ${codeToProcess}`;
        }

        // Case 3: IIFE
        else if (codeToProcess.startsWith('(function') || codeToProcess.startsWith('(async function')) {
            codeToProcess = `const result = ${codeToProcess}`;
        }

        // Case 4: Method shorthand
        else if (codeToProcess.match(/^[a-zA-Z_$][a-zA-Z0-9_$]*\s*\(/)) {
            codeToProcess = `const obj = {${codeToProcess}}`;
        }

        // Case 5: Generator functions
        else if (codeToProcess.startsWith('function*')) {
            codeToProcess = codeToProcess.startsWith('function* (')
                ? `const genFunc = ${codeToProcess}`
                : codeToProcess;
        }

        // Case 6: Async functions
        else if (codeToProcess.startsWith('async ')) {
            if (codeToProcess.startsWith('async function(')) {
                codeToProcess = `const asyncFunc = ${codeToProcess}`;
            } else if (codeToProcess.startsWith('async (')) {
                codeToProcess = `const asyncArrowFunc = ${codeToProcess}`;
            }
        }

        const ast = parse(codeToProcess, {
            sourceType: 'module',
            errorRecovery: true,
            plugins: [],
        });
        if (ast.errors && ast.errors.length > 0) {
            log('Parse warnings:', ast.errors);
        }
        traverse(ast, {
            MemberExpression(path) {
                // Kiểm tra đệ quy xem member expression có phải là một phần của call expression
                const isPartOfCallExpression = (currentPath: any): boolean => {
                    if (!currentPath) return false;
                    if (currentPath.isCallExpression()) return true;
                    if (currentPath.isMemberExpression()) {
                        return isPartOfCallExpression(currentPath.parentPath);
                    }
                    return false;
                };

                // Bỏ qua nếu member expression là một phần của call expression
                if (isPartOfCallExpression(path.parentPath)) {
                    return;
                }

                // Chỉ lấy property cuối cùng của member expression chain
                if (t.isIdentifier(path.node.property) && !path.node.computed) {
                    identifiers.add(path.node.property.name);
                }
            },

            Identifier(path) {
                // Kiểm tra đệ quy xem identifier có phải là một phần của call expression
                const isPartOfCallExpression = (currentPath: any): boolean => {
                    if (!currentPath) return false;

                    // Nếu gặp CallExpression, return true
                    if (currentPath.isCallExpression()) return true;

                    // Nếu vẫn trong MemberExpression chain, tiếp tục kiểm tra parent
                    if (currentPath.isMemberExpression()) {
                        return isPartOfCallExpression(currentPath.parentPath);
                    }

                    return false;
                };

                // Bỏ qua nếu identifier là một phần của call expression
                if (isPartOfCallExpression(path.parentPath)) {
                    return;
                }

                // Thu thập identifier khi nó được sử dụng làm tham số hoặc trong biểu thức
                const parentPath = path.parentPath;
                if (
                    t.isCallExpression(parentPath.node) ||
                    t.isAssignmentExpression(parentPath.node) ||
                    t.isConditionalExpression(parentPath.node) ||
                    t.isLogicalExpression(parentPath.node) ||
                    t.isTemplateLiteral(parentPath.node) ||
                    t.isForOfStatement(parentPath.node) ||
                    t.isForInStatement(parentPath.node) ||
                    t.isAwaitExpression(parentPath.node) ||
                    t.isThrowStatement(parentPath.node) ||
                    t.isYieldExpression(parentPath.node) ||
                    t.isExportSpecifier(parentPath.node) ||
                    t.isImportSpecifier(parentPath.node)
                ) {
                    identifiers.add(path.node.name);
                }

                // Xử lý object shorthand { API_KEY }
                if (t.isObjectProperty(parentPath.node) && parentPath.node.shorthand) {
                    identifiers.add(path.node.name);
                }

                // Xử lý object property key { globalId: value }
                if (t.isObjectProperty(parentPath.node) && parentPath.node.key === path.node && !parentPath.node.computed) {
                    identifiers.add(path.node.name);
                }

                // Thêm điều kiện cho destructuring assignment
                if (t.isObjectPattern(parentPath?.node)) {
                    // Chỉ thu thập nếu nằm bên phải phép gán
                    if (parentPath.parentPath?.isVariableDeclarator() &&
                        parentPath.parentPath.node.id !== parentPath.node) {
                        identifiers.add(path.node.name);
                    }
                }
            }
        });
    } catch (error) {
        log('Failed to parse code:', error);
        log('Code snippet:', code.slice(0, 100));
        if (error instanceof SyntaxError) {
            log('Syntax error at position:', (error as any).pos);
        }
    }

    return identifiers;
} 