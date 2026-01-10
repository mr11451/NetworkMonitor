//{{NO_DEPENDENCIES}}
// Microsoft Visual C++ で生成されたインクルード ファイルです。
// NetworkMonitorApp.rc で使用
//
#define IDC_MYICON                      2
#define IDD_NETWORKMONITORAPP_DIALOG    102
#define IDS_APP_TITLE                   103
#define IDD_ABOUTBOX                    106
#define IDM_ABOUT                       104
#define IDM_EXIT                        105
#define IDI_NETWORKMONITORAPP           107
#define IDI_SMALL                       108
#define IDC_NETWORKMONITORAPP           109
#define IDR_MAINFRAME                   128
#define IDM_VIEW_LOG                    32771
#define IDR_MAINMENU                    129
#define IDD_MAIN_DIALOG                 130
#define IDD_LOG_WINDOW                  131

//-----------------------------
// コントロールID
//-----------------------------
#define IDC_STATIC_PORT_LABEL           1006
#define IDC_EDIT_PORT_NUMBER            1000
#define IDC_BTN_TOGGLE_CAPTURE          1005
#define IDC_BTN_SHOW_LOG                1004
#define IDC_STATIC_STATUS               1007
#define IDC_BTN_SELECT_LOG_FOLDER       1008
#define IDC_STATIC_LOG_PATH             1009
#define IDC_LOG_BTN_CLEAR               1010
#define IDC_LOG_BTN_OPEN_FOLDER         1011
#define IDC_LOG_STATIC_PATH             1012
#define IDC_LOG_LISTBOX                 1013
#define IDC_BTN_START_CUSTOM            1001
#define IDC_BTN_TOGGLE_MONITOR          1001
#define IDC_STATIC_IP_LABEL             1014
#define IDC_EDIT_TARGET_IP              1015

//-----------------------------
// 文字列リソースID
//-----------------------------

// --- エラー・警告・情報メッセージ ---
#define IDS_ERROR_PORT_RANGE            200   // ポート範囲エラー
#define IDS_ERROR_TITLE                 201   // エラーダイアログタイトル
#define IDS_INFO_TITLE                  202   // 情報ダイアログタイトル
#define IDS_ERROR_ALREADY_CAPTURING     203   // 既にキャプチャ中
#define IDS_INFO_CAPTURE_STARTED        204   // キャプチャ開始通知
#define IDS_ERROR_CAPTURE_FAILED        205   // キャプチャ失敗
#define IDS_INFO_CAPTURE_STOPPED        206   // キャプチャ停止通知
#define IDS_CONFIRM_EXIT                207   // 終了確認
#define IDS_CONFIRM_TITLE               208   // 確認ダイアログタイトル

// --- ステータス表示 ---
#define IDS_STATUS_RUNNING              209   // 実行中
#define IDS_STATUS_STOPPED              210   // 停止中
#define IDS_STATUS_PACKET_COUNT         211   // パケット数
#define IDS_STATUS_USAGE                212   // 使い方
#define IDS_STATUS_ADMIN_REQUIRED       214   // 管理者権限必要
#define IDS_DEFAULT_PORT                215   // デフォルトポート

// --- バイナリログ関連 ---
#define IDS_BINARY_LOG_STARTED          216   // バイナリログ開始
#define IDS_BINARY_LOG_STOPPED          217   // バイナリログ停止

// --- ログウィンドウ ---
#define IDS_LOG_WINDOW_TITLE            218   // ログウィンドウタイトル
#define IDS_LOG_BUTTON_CLEAR            219   // クリアボタン
#define IDS_LOG_BUTTON_OPEN_FOLDER      220   // フォルダを開くボタン
#define IDS_LOG_LABEL_PATH_PREFIX       221   // ログパスラベル（接頭辞）
#define IDS_LOG_LABEL_PATH_UNSET        222   // ログパス未設定
#define IDS_LOG_ERROR_PATH_NOT_SET      223   // ログパス未設定エラー

// --- ログフォルダ選択 ---
#define IDS_SELECT_LOG_FOLDER           224   // フォルダ選択ダイアログタイトル
#define IDS_LOG_FOLDER_SELECTED         225   // フォルダ選択完了

// --- PacketCapture関連 ---
#define IDS_ERROR_WSASTARTUP_FAILED     226   // Winsock初期化失敗
#define IDS_ERROR_RAW_SOCKET_FAILED     227   // RAWソケット生成失敗
#define IDS_ERROR_ADMIN_REQUIRED        228   // 管理者権限必要（重複注意）
#define IDS_ERROR_HOSTNAME_FAILED       229   // ホスト名取得失敗
#define IDS_ERROR_ADDRINFO_FAILED       230   // アドレス情報取得失敗
#define IDS_ERROR_BIND_FAILED           231   // バインド失敗
#define IDS_ERROR_PROMISCUOUS_FAILED    232   // プロミスキャス失敗
#define IDS_RAW_SOCKET_INITIALIZED      233   // RAWソケット初期化成功
#define IDS_ALREADY_CAPTURING           234   // 既にキャプチャ中（重複注意）
#define IDS_CAPTURE_STARTED             235   // キャプチャ開始
#define IDS_CAPTURE_STOPPED             236   // キャプチャ停止
#define IDS_CAPTURE_THREAD_STARTED      237   // キャプチャスレッド開始
#define IDS_SOCKET_ERROR                238   // ソケットエラー
#define IDS_CAPTURE_THREAD_ENDED        239   // キャプチャスレッド終了

// --- トグルボタン ---
#define IDS_BTN_START_CAPTURE           240   // 開始ボタン
#define IDS_BTN_STOP_CAPTURE            241   // 停止ボタン

// --- IPアドレス検証 ---
#define IDS_ERROR_INVALID_IP            242   // 無効なIP
#define IDS_IP_LABEL                    243   // IPラベル

// --- AppController関連 ---
#define IDS_CAPTURE_ALL_IP_IPV4_IPV6    244   // 全IPキャプチャ
#define IDS_CAPTURE_TARGET_IP           245   // 対象IPキャプチャ
#define IDS_LOG_FOLDER_CHANGE_TITLE     246   // ログフォルダ変更タイトル
#define IDS_LOG_FOLDER_CHANGE_MSG       247   // ログフォルダ変更メッセージ
#define IDS_ERROR_LOG_FOLDER_NOT_FOUND  248   // ログフォルダ未検出
#define IDS_ERROR_DIR_CREATE_FAILED     249   // ディレクトリ作成失敗
#define IDS_LOG_FOLDER_SELECT_TITLE     250   // ログフォルダ選択タイトル

// --- PacketCapture共通メッセージ ---
#define IDS_PCAP_FINDALLDEVS_FAILED     260   // インターフェース列挙失敗
#define IDS_PCAP_OPEN_LIVE_FAILED       261   // pcap_open_live失敗
#define IDS_PCAP_NO_IPV4_INTERFACE      262   // IPv4インターフェースなし
#define IDS_PCAP_NO_IPV6_INTERFACE      263   // IPv6インターフェースなし
#define IDS_PCAP_COMPILE_FAILED         264   // pcap_compile失敗
#define IDS_PCAP_SETFILTER_FAILED       265   // pcap_setfilter失敗
#define IDS_PCAP_INITIALIZED_IPV4       266   // npcap初期化成功(IPv4)
#define IDS_PCAP_INITIALIZED_IPV6       267   // npcap初期化成功(IPv6)
#define IDS_CAPTURE_STARTED_IPV4        268   // IPv4キャプチャ開始
#define IDS_CAPTURE_STARTED_IPV6        269   // IPv6キャプチャ開始
#define IDS_CAPTURE_STOPPED_IPV4        270   // IPv4キャプチャ停止
#define IDS_CAPTURE_STOPPED_IPV6        271   // IPv6キャプチャ停止

//-----------------------------
// 次のデフォルト値
//-----------------------------
#ifdef APSTUDIO_INVOKED
#ifndef APSTUDIO_READONLY_SYMBOLS
#define _APS_NO_MFC                     1
#define _APS_NEXT_RESOURCE_VALUE        132
#define _APS_NEXT_COMMAND_VALUE         32772
#define _APS_NEXT_CONTROL_VALUE         1016
#define _APS_NEXT_SYMED_VALUE           110
#endif
#endif
