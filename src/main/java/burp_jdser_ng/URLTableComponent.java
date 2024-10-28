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
import java.util.List;
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
    private final List<URL> urlList = new ArrayList<>();

    private final JTable classPathTable;
    private final DefaultTableModel classPathTableModel;
    private final DefaultTableModel discoveredClassesLogTableModel;
    private final DefaultTableModel outputLogTableModel;
    private final DefaultTableModel errorLogTableModel;

    public final JButton reloadButton = new JButton("Reload");

    public URLTableComponent(MontoyaApi api) {
        this.api = api;
        setLayout(new BorderLayout());

        classPathTableModel = new DefaultTableModel(new Object[]{"Class Path"}, 0);
        classPathTable = new JTable(classPathTableModel);
        JPanel classPathPanel = createPanelWithTable(classPathTable, Map.of("Add", e -> addFile(),
                "Remove", e -> removeSelectedFile(),
                "Clear", e -> clearFiles(),
                "Reload", e -> reloadButton.doClick()
        ));

        discoveredClassesLogTableModel = new DefaultTableModel(new Object[]{"Discovered Classes"}, 0);
        JPanel discoveredClassesPanel = createPanelWithTable(new JTable(discoveredClassesLogTableModel), Map.of(
                "Clear", e -> clearTable(discoveredClassesLogTableModel)
        ));

        outputLogTableModel = new DefaultTableModel(new Object[]{"Output Log"}, 0);
        JPanel outputLogPanel = createPanelWithTable(new JTable(outputLogTableModel), Map.of(
                "Clear", e -> clearTable(outputLogTableModel)
        ));

        errorLogTableModel = new DefaultTableModel(new Object[]{"Error Log"}, 0);
        JPanel errorLogPanel = createPanelWithTable(new JTable(errorLogTableModel), Map.of(
                "Clear", e -> clearTable(errorLogTableModel)
        ));

        JPanel mainPanel = new JPanel(new GridLayout(2, 2));
        mainPanel.add(classPathPanel);
        mainPanel.add(discoveredClassesPanel);
        mainPanel.add(outputLogPanel);
        mainPanel.add(errorLogPanel);
        add(mainPanel, BorderLayout.CENTER);

        loadFiles();
    }

    public void addDiscoveredClassLog(String log) {
        SwingUtilities.invokeLater(() -> discoveredClassesLogTableModel.addRow(new Object[]{log}));
    }

    public void clearDiscoveredClassesLog() {
        SwingUtilities.invokeLater(() -> discoveredClassesLogTableModel.setRowCount(0));
    }

    public void addOutputLog(String log) {
        SwingUtilities.invokeLater(() -> outputLogTableModel.addRow(new Object[]{log}));
    }

    public void addErrorLog(String log) {
        SwingUtilities.invokeLater(() -> errorLogTableModel.addRow(new Object[]{log}));
    }

    private void loadFiles() {
        String urls = api.persistence().preferences().getString("jdser:urls");
        if (urls == null) {
            return;
        }
        if (!urls.isEmpty()) {
            for (String urlString : urls.split(";")) {
                try {
                    URL url = new URI(urlString).toURL();
                    urlList.add(url);
                    classPathTableModel.addRow(new Object[]{url});
                } catch (MalformedURLException | URISyntaxException e) {
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
            File selectedFile = fileChooser.getSelectedFile();
            try {
                URL url = selectedFile.toURI().toURL();
                urlList.add(url);
                classPathTableModel.addRow(new Object[]{url});
            } catch (MalformedURLException ex) {
                JOptionPane.showMessageDialog(this, "Error adding URL: " + ex.getMessage());
            }
            saveURLs();
        }
    }

    private void removeSelectedFile() {
        int selectedRow = classPathTable.getSelectedRow();
        if (selectedRow != -1) {
            classPathTableModel.removeRow(selectedRow);
            urlList.remove(selectedRow);
            saveURLs();
        }
    }

    private void clearFiles() {
        classPathTableModel.setRowCount(0);
        urlList.clear();
        saveURLs();
    }

    private void clearTable(DefaultTableModel model) {
        model.setRowCount(0);
    }

    public URL[] getURLs() {
        return urlList.toArray(URL[]::new);
    }

    private void saveURLs() {
        StringBuilder urls = new StringBuilder(urlList.size() * 50); // Estimate size
        for (URL url : urlList) {
            urls.append(url).append(";");
        }
        api.logging().logToOutput("Saving URLs: " + urls);
        api.persistence().preferences().setString("jdser:urls", urls.toString());
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
