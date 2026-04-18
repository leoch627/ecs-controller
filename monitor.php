<?php
// 此文件用于 Cron 任务
// 输出简洁的文本日志

require_once 'AliyunTrafficCheck.php';

// ---- 并发锁：防止多个 Cron 实例同时运行导致 API 请求堆叠、机器过载 ----
// 锁文件放在可写的 data/ 目录下；LOCK_NB 确保拿不到锁时立刻退出而不是等待。
$_lockFile = __DIR__ . '/data/.monitor.lock';
$_lockFp   = @fopen($_lockFile, 'c');
if (!$_lockFp || !flock($_lockFp, LOCK_EX | LOCK_NB)) {
    // 上一次巡检仍在运行，跳过本次 Cron tick
    if ($_lockFp) {
        fclose($_lockFp);
    }
    exit(0);
}
// 注册退出时自动释放锁（包括致命错误、exit、正常结束）
register_shutdown_function(function () use ($_lockFp) {
    flock($_lockFp, LOCK_UN);
    fclose($_lockFp);
});

header('Content-Type: text/plain; charset=utf-8');

$app = new AliyunTrafficCheck();

// CLI 模式直接运行，Web 模式使用 Bearer Token 鉴权
$isCli = (PHP_SAPI === 'cli');

if (!$isCli) {
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['HTTP_X_MONITOR_TOKEN'] ?? '';
    if (preg_match('/^Bearer\s+(.+)$/i', $authHeader, $matches)) {
        $authHeader = $matches[1];
    }

    $monitorKey = $app->getMonitorKey();
    if (empty($monitorKey) || !hash_equals($monitorKey, $authHeader)) {
        http_response_code(403);
        echo "访问被拒绝，请使用有效的监控密钥。";
        exit;
    }
}

// 输出简洁日志
echo "--- ECS 服务器管理 开始检测: " . date('Y-m-d H:i:s') . " ---\n";
echo $app->monitor();
echo "\n--- 检测结束 ---\n";
