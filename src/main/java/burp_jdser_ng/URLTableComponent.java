package burp_jdser_ng;

import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.io.File;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Map;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;

import burp.api.montoya.MontoyaApi;

public class URLTableComponent extends JPanel {

    private final MontoyaApi api;
    private final ArrayList<URL> jarList = new ArrayList<>();

    private final JTable classPathTable;
    private final DefaultTableModel classPathTableModel;
    private final DefaultTableModel discoveredClassesLogTableModel;
    private final DefaultTableModel outputLogTableModel;
    private final DefaultTableModel errorLogTableModel;

    public final JButton reloadButton = new JButton("Reload");

    private final String perfName = "jdser:paths";

    public URLTableComponent(MontoyaApi api) {
        this.api = api;
        setLayout(new BorderLayout());

        classPathTableModel = new DefaultTableModel(new Object[] { "Class Path" }, 0);
        classPathTable = new JTable(classPathTableModel);
        JPanel classPathPanel = createPanelWithTable(classPathTable, Map.of("Add", e -> addFile(),
                "Remove", e -> removeSelectedFile(),
                "Clear", e -> clearFiles(),
                "Reload", e -> reloadButton.doClick()));

        discoveredClassesLogTableModel = new DefaultTableModel(new Object[] { "Discovered Classes" }, 0);
        JPanel discoveredClassesPanel = createPanelWithTable(new JTable(discoveredClassesLogTableModel), Map.of(
                "Clear", e -> clearTable(discoveredClassesLogTableModel)));

        outputLogTableModel = new DefaultTableModel(new Object[] { "Output Log" }, 0);
        JPanel outputLogPanel = createPanelWithTable(new JTable(outputLogTableModel), Map.of(
                "Clear", e -> clearTable(outputLogTableModel)));

        errorLogTableModel = new DefaultTableModel(new Object[] { "Error Log" }, 0);
        JPanel errorLogPanel = createPanelWithTable(new JTable(errorLogTableModel), Map.of(
                "Clear", e -> clearTable(errorLogTableModel)));

        JPanel mainPanel = new JPanel(new GridLayout(2, 2));
        mainPanel.add(classPathPanel);
        mainPanel.add(discoveredClassesPanel);
        mainPanel.add(outputLogPanel);
        mainPanel.add(errorLogPanel);
        add(mainPanel, BorderLayout.CENTER);

        loadPerfs();
    }

    public void addDiscoveredClassLog(String log) {
        SwingUtilities.invokeLater(() -> discoveredClassesLogTableModel.addRow(new Object[] { log }));
    }

    public void clearDiscoveredClassesLog() {
        SwingUtilities.invokeLater(() -> discoveredClassesLogTableModel.setRowCount(0));
    }

    public void addOutputLog(String log) {
        SwingUtilities.invokeLater(() -> outputLogTableModel.addRow(new Object[] { log }));
    }

    public void addErrorLog(String log) {
        SwingUtilities.invokeLater(() -> errorLogTableModel.addRow(new Object[] { log }));
    }

    private void loadPerfs() {
        String urls = api.persistence().preferences().getString(perfName);
        if (urls != null && !urls.isEmpty()) {
            for (String urlString : urls.split(";")) {
                api.logging().logToOutput("Loading path: " + urlString);
                try {
                    URL jarPath = new URI(urlString).toURL();
                    jarList.add(jarPath);
                    classPathTableModel.addRow(new Object[] { jarPath });
                } catch (URISyntaxException | MalformedURLException e) {
                    JOptionPane.showMessageDialog(this, "Error loading URL: " + e.getMessage());
                }
            }
        }
    }

    private void addFile() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileFilter(new javax.swing.filechooser.FileFilter() {
            @Override
            public boolean accept(File f) {
                return f.isDirectory() || f.getName().toLowerCase().endsWith(".jar");
            }

            @Override
            public String getDescription() {
                return "JAR Files (*.jar)";
            }
        });

        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                File selectedFile = fileChooser.getSelectedFile();
                URL jarPath;
                jarPath = selectedFile.toURI().toURL();
                jarList.add(jarPath);
                classPathTableModel.addRow(new Object[] { jarPath });
                persist();
            } catch (MalformedURLException ex) {
                JOptionPane.showMessageDialog(this, "Error loading URL: " + ex.getMessage());
            }
            persist();
        }

    }

    private void removeSelectedFile() {
        int selectedRow = classPathTable.getSelectedRow();
        if (selectedRow != -1) {
            classPathTableModel.removeRow(selectedRow);
            jarList.remove(selectedRow);
            persist();
        }
    }

    private void clearFiles() {
        classPathTableModel.setRowCount(0);
        jarList.clear();
        persist();
    }

    private void clearTable(DefaultTableModel model) {
        model.setRowCount(0);
    }

    public URL[] getURLs() {
        return jarList.toArray(URL[]::new);
    }

    private void persist() {
        StringBuilder urls = new StringBuilder();
        for (URL url : jarList) {
            urls.append(url.toString()).append(";");
        }
        api.logging().logToOutput("Saving paths: " + urls);
        api.persistence().preferences().setString(perfName, urls.toString());
        reloadButton.doClick();
    }

    private JPanel createPanelWithTable(JTable table, Map<String, java.util.function.Consumer<ActionEvent>> buttons) {
        JPanel panel = new JPanel(new BorderLayout());
        JPanel buttonPanel = new JPanel();
        buttons.forEach((text, action) -> addButton(buttonPanel, text, action));
        panel.add(table.getTableHeader(), BorderLayout.NORTH);
        panel.add(buttonPanel, BorderLayout.SOUTH);
        panel.add(new JScrollPane(table), BorderLayout.CENTER);
        return panel;
    }

    private void addButton(JPanel panel, String text, java.util.function.Consumer<ActionEvent> action) {
        JButton button = new JButton(text);
        button.addActionListener(action::accept);
        panel.add(button);
    }
}
