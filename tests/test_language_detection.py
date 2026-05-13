"""
Language detection confidence tests.
All cases must detect correct language with >= 0.95 confidence.
Run: python3 -m pytest tests/test_language_detection.py -v
"""
import sys
import pytest

sys.path.insert(0, 'backend/src')
from language_detector import detect_language

THRESHOLD = 0.95

def _check(code, expected_lang, label=""):
    detected, conf = detect_language(code)
    assert detected == expected_lang, (
        f"{label}: expected {expected_lang}, got {detected} (conf={conf:.2f})"
    )
    assert conf >= THRESHOLD, (
        f"{label}: correct lang but conf={conf:.2f} < {THRESHOLD}"
    )


# ── Python ────────────────────────────────────────────────────────────────────

class TestPython:
    def test_full_module(self):
        _check('''
import os
from pathlib import Path

def process(items):
    self.results = []
    for item in items:
        if item > 0:
            self.results.append(item)
        elif len(items) == 0:
            return None
    return self.results
''', 'python', 'python full')

    def test_sparse_function(self):
        _check('''
def check(x):
    if x > 0:
        return True
    elif x == 0:
        return None
''', 'python', 'python sparse')

    def test_class_with_self(self):
        _check('''
class Scanner:
    def __init__(self, path):
        self.path = path

    def run(self):
        for f in os.listdir(self.path):
            self.process(f)
''', 'python', 'python class')

    def test_true_false_none(self):
        _check('''
def validate(x):
    if x is None:
        return False
    return True
''', 'python', 'python True/False/None')

    def test_decorator(self):
        _check('''
@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json()
    return jsonify({"result": "ok"})
''', 'python', 'python decorator')

    def test_comprehension(self):
        _check('''
def clean(items):
    return [x for x in items if x is not None]
''', 'python', 'python comprehension')


# ── Java ─────────────────────────────────────────────────────────────────────

class TestJava:
    def test_full_class(self):
        _check('''
import java.util.ArrayList;
public class UserService {
    private String username;
    public static void main(String[] args) {
        System.out.println("hello");
    }
}
''', 'java', 'java full')

    def test_sparse_main(self):
        _check('''
public class Foo {
    public static void main(String[] args) {
        System.out.println("hi");
    }
}
''', 'java', 'java sparse')

    def test_string_param_no_imports(self):
        _check('''
unsigned long hexToDec(String hexString) {
    unsigned long ret;
    for(int i=0; i < hexString.length(); ++i) {
        int val = getVal(hexString[i]);
        ret = ret * 16 + val;
    }
    return ret;
}
''', 'java', 'java String param no imports')

    def test_for_int_loop(self):
        _check('''
void process(String[] items) {
    for(int i=0; i < items.length(); ++i) {
        System.out.println(items[i]);
    }
}
''', 'java', 'java for(int) loop')

    def test_jdbc(self):
        _check('''
Connection conn = DriverManager.getConnection(url);
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id=?");
stmt.setInt(1, userId);
ResultSet rs = stmt.executeQuery();
''', 'java', 'java jdbc')


# ── C ────────────────────────────────────────────────────────────────────────

class TestC:
    def test_with_includes(self):
        _check('''
#include <stdio.h>
#include <string.h>
void login(char *input) {
    char buffer[8];
    strcpy(buffer, input);
    printf("%s", buffer);
}
int main(int argc, char *argv[]) { return 0; }
''', 'c', 'c with includes')

    def test_no_includes_strcpy(self):
        _check('''
void login(char *input) {
    char buffer[8];
    strcpy(buffer, input);
}
''', 'c', 'c no includes strcpy')

    def test_just_strcpy(self):
        _check('strcpy(dest, src);', 'c', 'c just strcpy')

    def test_gets_vuln(self):
        _check('''
void read_input() {
    char buf[64];
    gets(buf);
}
''', 'c', 'c gets vuln')

    def test_uninitialized_var(self):
        _check('''
unsigned long hexToDec(char *s) {
    unsigned long ret;
    ret = ret * 16;
    return ret;
}
''', 'c', 'c uninitialized var')

    def test_format_string(self):
        _check('''
void log_msg(char *user_input) {
    printf(user_input);
}
''', 'c', 'c format string vuln')

    def test_heap_operations(self):
        _check('''
char *buf = malloc(256);
if (!buf) return NULL;
memcpy(buf, src, len);
free(buf);
''', 'c', 'c heap ops')


# ── C++ ───────────────────────────────────────────────────────────────────────

class TestCpp:
    def test_full(self):
        _check('''
#include <iostream>
#include <vector>
using namespace std;
class Node {
public:
    int val;
    Node(int v) : val(v) {}
};
int main() {
    vector<Node*> nodes;
    cout << "hello" << endl;
    return 0;
}
''', 'cpp', 'cpp full')

    def test_sparse(self):
        _check('''
#include <iostream>
using namespace std;
int main() {
    cout << "hello" << endl;
}
''', 'cpp', 'cpp sparse')

    def test_stl(self):
        _check('''
#include <vector>
#include <string>
std::vector<std::string> split(const std::string& s) {
    std::vector<std::string> result;
    return result;
}
''', 'cpp', 'cpp STL')


# ── Go ───────────────────────────────────────────────────────────────────────

class TestGo:
    def test_full(self):
        _check('''
package main
import (
    "fmt"
    "net/http"
)
func handler(w http.ResponseWriter, r *http.Request) {
    ch := make(chan int)
    go func() { ch <- 1 }()
    defer r.Body.Close()
    fmt.Println("ok")
}
''', 'go', 'go full')

    def test_sparse(self):
        _check('''
package main
import "fmt"
func main() {
    fmt.Println("hello")
}
''', 'go', 'go sparse')

    def test_goroutine(self):
        _check('''
package main
func process(data []byte) error {
    ch := make(chan error)
    go func() {
        ch <- nil
    }()
    return <-ch
}
''', 'go', 'go goroutine')


# ── Rust ─────────────────────────────────────────────────────────────────────

class TestRust:
    def test_full(self):
        _check('''
use std::collections::HashMap;
pub fn process(data: &mut Vec<u8>) -> Result<(), String> {
    let mut map: HashMap<String, u32> = HashMap::new();
    match data.len() {
        0 => return Err(String::from("empty")),
        _ => println!("{:?}", data),
    }
    Ok(())
}
''', 'rust', 'rust full')

    def test_sparse(self):
        _check('''
fn main() {
    let mut x = 5;
    println!("{}", x);
}
''', 'rust', 'rust sparse')

    def test_result_type(self):
        _check('''
fn read_file(path: &str) -> Result<String, std::io::Error> {
    let mut s = String::new();
    Ok(s)
}
''', 'rust', 'rust Result type')


# ── JavaScript ───────────────────────────────────────────────────────────────

class TestJavaScript:
    def test_full(self):
        _check('''
const express = require("express");
const app = express();
const fetchData = async () => {
    const result = await fetch("/api");
    console.log(result);
};
export default fetchData;
''', 'javascript', 'js full')

    def test_sparse(self):
        _check('''
const x = require("fs");
const data = x.readFileSync("file.txt");
console.log(data);
''', 'javascript', 'js sparse')

    def test_dom(self):
        _check('''
document.getElementById("btn").addEventListener("click", () => {
    window.location.href = "/dashboard";
    console.log("navigated");
});
''', 'javascript', 'js DOM')


# ── TypeScript ────────────────────────────────────────────────────────────────

class TestTypeScript:
    def test_full(self):
        _check('''
interface User {
    id: number;
    name: string;
}
type ApiResponse = Readonly<{data: User[]}>;
const getUser = <T>(id: number): T => {
    return {} as T;
};
''', 'typescript', 'ts full')

    def test_sparse(self):
        _check('''
interface Config {
    timeout: number;
    retries: boolean;
}
const cfg: Config = { timeout: 30, retries: true };
''', 'typescript', 'ts sparse')

    def test_enum(self):
        _check('''
enum Status {
    Active,
    Inactive,
    Pending
}
const s: Status = Status.Active;
''', 'typescript', 'ts enum')


# ── Ruby ─────────────────────────────────────────────────────────────────────

class TestRuby:
    def test_full(self):
        _check('''
require "net/http"
class UserService
    attr_accessor :name, :email
    def initialize(name)
        @name = name
    end
    def fetch_data
        [1,2,3].each do |x|
            puts x
        end
    end
end
''', 'ruby', 'ruby full')

    def test_sparse(self):
        _check('''
def greet(name)
    puts "Hello #{name}"
end
greet("world")
''', 'ruby', 'ruby sparse')


# ── PHP ──────────────────────────────────────────────────────────────────────

class TestPHP:
    def test_full(self):
        _check('''
<?php
$conn = new PDO("mysql:host=localhost", $user, $pass);
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);
echo json_encode($stmt->fetchAll());
function validate($input) { return htmlspecialchars($input); }
''', 'php', 'php full')

    def test_sparse(self):
        _check('$x = $_GET["id"];\necho $x;', 'php', 'php sparse')


# ── Kotlin ───────────────────────────────────────────────────────────────────

class TestKotlin:
    def test_full(self):
        _check('''
data class User(val id: Int, val name: String)
suspend fun fetchUser(id: Int): User {
    val result = withContext(Dispatchers.IO) { api.getUser(id) }
    return result
}
companion object { fun create(): UserService = UserService() }
''', 'kotlin', 'kotlin full')

    def test_sparse(self):
        _check('''
fun greet(name: String) {
    val msg = "Hello $name"
    println(msg)
}
''', 'kotlin', 'kotlin sparse')


# ── Swift ────────────────────────────────────────────────────────────────────

class TestSwift:
    def test_full(self):
        _check('''
import Foundation
import UIKit
@State private var isLoading = false
struct ContentView: View {
    var body: some View { Text("Hello") }
}
guard let url = URL(string: "https://api.example.com") else { return }
''', 'swift', 'swift full')

    def test_sparse(self):
        _check('''
import Foundation
let url = URL(string: "https://api.example.com")!
guard let data = try? Data(contentsOf: url) else { return }
print(data)
''', 'swift', 'swift sparse')


# ── C# ───────────────────────────────────────────────────────────────────────

class TestCSharp:
    def test_full(self):
        _check('''
using System;
using System.Collections.Generic;
namespace MyApp {
    public class UserService {
        public async Task<string> GetUserAsync(int id) {
            Console.WriteLine($"Fetching {id}");
            return await dbContext.Users.FindAsync(id);
        }
    }
}
''', 'c_sharp', 'c# full')

    def test_sparse(self):
        _check('''
using System;
class Program {
    static void Main() {
        Console.WriteLine("hi");
    }
}
''', 'c_sharp', 'c# sparse')


# ── Extension-based (filename hint) ──────────────────────────────────────────

class TestFilenameHint:
    def test_py_extension(self):
        code = 'x = 1'
        detected, conf = detect_language(code, filename='script.py')
        assert detected == 'python' and conf == 1.0

    def test_c_extension(self):
        code = 'int x = 0;'
        detected, conf = detect_language(code, filename='main.c')
        assert detected == 'c' and conf == 1.0

    def test_ts_extension(self):
        code = 'const x = 1'
        detected, conf = detect_language(code, filename='app.ts')
        assert detected == 'typescript' and conf == 1.0

    def test_go_extension(self):
        code = 'x := 1'
        detected, conf = detect_language(code, filename='main.go')
        assert detected == 'go' and conf == 1.0


# ── Edge cases ────────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_empty_defaults_python_zero_conf(self):
        detected, conf = detect_language('')
        assert detected == 'python'
        assert conf == 0.0

    def test_whitespace_only(self):
        detected, conf = detect_language('   \n\n   ')
        assert detected == 'python'
        assert conf == 0.0

    def test_comment_only(self):
        # Comments alone shouldn't give high confidence
        detected, conf = detect_language('// This is a comment\n// Another line')
        assert conf < THRESHOLD

    def test_single_strcpy_is_c(self):
        detected, conf = detect_language('strcpy(dst, src);')
        assert detected == 'c'
        assert conf >= THRESHOLD

    def test_single_gets_is_c(self):
        detected, conf = detect_language('gets(buffer);')
        assert detected == 'c'
        assert conf >= THRESHOLD
