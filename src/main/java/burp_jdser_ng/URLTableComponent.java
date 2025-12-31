package burp_jdser_ng;

import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

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
    private final Set<String> jarKeys = new HashSet<>();

    private final JTable classPathTable;
    private final DefaultTableModel classPathTableModel;
    private final DefaultTableModel discoveredClassesLogTableModel;
    private final DefaultTableModel outputLogTableModel;
    private final DefaultTableModel errorLogTableModel;

    public final JButton reloadButton = new JButton("Reload");

    private final String perfName = "jdser:paths";

    private record ButtonDef(String text, java.util.function.Consumer<ActionEvent> action) {
    }

    public URLTableComponent(MontoyaApi api) {
        this.api = api;
        setLayout(new BorderLayout());

        classPathTableModel = new DefaultTableModel(new Object[] { "Class Path" }, 0);
        classPathTable = new JTable(classPathTableModel);
        JPanel classPathPanel = createPanelWithTable(classPathTable, List.of(
                new ButtonDef("Add JAR", e -> addFile()),
                new ButtonDef("Add Folder", e -> addFolder()),
                new ButtonDef("Remove", e -> removeSelectedFile()),
                new ButtonDef("Clear", e -> clearFiles()),
                new ButtonDef("Reload", e -> reloadButton.doClick())));

        discoveredClassesLogTableModel = new DefaultTableModel(new Object[] { "Discovered Classes" }, 0);
        JPanel discoveredClassesPanel = createPanelWithTable(new JTable(discoveredClassesLogTableModel), List.of(
                new ButtonDef("Clear", e -> clearTable(discoveredClassesLogTableModel))));

        outputLogTableModel = new DefaultTableModel(new Object[] { "Output Log" }, 0);
        JPanel outputLogPanel = createPanelWithTable(new JTable(outputLogTableModel), List.of(
                new ButtonDef("Clear", e -> clearTable(outputLogTableModel))));

        errorLogTableModel = new DefaultTableModel(new Object[] { "Error Log" }, 0);
        JPanel errorLogPanel = createPanelWithTable(new JTable(errorLogTableModel), List.of(
                new ButtonDef("Clear", e -> clearTable(errorLogTableModel))));

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
                    addJarUrlInternal(jarPath);
                } catch (URISyntaxException | MalformedURLException e) {
                    JOptionPane.showMessageDialog(this, "Error loading URL: " + e.getMessage());
                }
            }
        }
    }

    private static String urlKey(URL url) {
        try {
            return url.toURI().normalize().toString();
        } catch (URISyntaxException e) {
            return url.toString();
        }
    }

    private boolean addJarUrlInternal(URL jarUrl) {
        String key = urlKey(jarUrl);
        if (!jarKeys.add(key)) {
            return false;
        }
        jarList.add(jarUrl);
        classPathTableModel.addRow(new Object[] { jarUrl });
        return true;
    }

    private void addFile() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
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
                if (selectedFile == null || !selectedFile.isFile()
                        || !selectedFile.getName().toLowerCase().endsWith(".jar")) {
                    JOptionPane.showMessageDialog(this, "Please select a .jar file.");
                    return;
                }
                URL jarPath = selectedFile.toURI().toURL();
                boolean added = addJarUrlInternal(jarPath);
                if (!added) {
                    addOutputLog("Skipped duplicate JAR: " + selectedFile.getAbsolutePath());
                    return;
                }
            } catch (MalformedURLException ex) {
                JOptionPane.showMessageDialog(this, "Error loading URL: " + ex.getMessage());
                return;
            }
            persist();
        }

    }

    private void addFolder() {
        JFileChooser folderChooser = new JFileChooser();
        folderChooser.setDialogTitle("Select folder containing JAR files");
        folderChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        folderChooser.setAcceptAllFileFilterUsed(false);

        if (folderChooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File folder = folderChooser.getSelectedFile();
        if (folder == null || !folder.isDirectory()) {
            JOptionPane.showMessageDialog(this, "Please select a valid folder.");
            return;
        }

        List<File> jarFiles;
        try {
            try (var paths = java.nio.file.Files.walk(folder.toPath())) {
                jarFiles = paths
                        .filter(java.nio.file.Files::isRegularFile)
                        .filter(p -> p.getFileName().toString().toLowerCase().endsWith(".jar"))
                        .sorted()
                        .map(java.nio.file.Path::toFile)
                        .toList();
            }
        } catch (IOException e) {
            JOptionPane.showMessageDialog(this, "Error reading folder: " + e.getMessage());
            return;
        }

        if (jarFiles.isEmpty()) {
            addOutputLog("No .jar files found in folder: " + folder.getAbsolutePath());
            return;
        }

        int addedCount = 0;
        int skippedCount = 0;
        for (File jarFile : jarFiles) {
            try {
                URL jarUrl = jarFile.toURI().toURL();
                boolean added = addJarUrlInternal(jarUrl);
                if (added) {
                    addedCount++;
                } else {
                    skippedCount++;
                }
            } catch (MalformedURLException e) {
                addErrorLog("Failed to add JAR (" + jarFile.getAbsolutePath() + "): " + e.getMessage());
            }
        }

        addOutputLog("Added " + addedCount + " JAR(s) from folder: " + folder.getAbsolutePath()
                + (skippedCount > 0 ? " (skipped " + skippedCount + " duplicate(s))" : ""));
        if (addedCount > 0) {
            persist();
        }
    }

    private void removeSelectedFile() {
        int selectedRow = classPathTable.getSelectedRow();
        if (selectedRow != -1) {
            URL removed = jarList.get(selectedRow);
            classPathTableModel.removeRow(selectedRow);
            jarList.remove(selectedRow);
            jarKeys.remove(urlKey(removed));
            persist();
        }
    }

    private void clearFiles() {
        classPathTableModel.setRowCount(0);
        jarList.clear();
        jarKeys.clear();
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

    private JPanel createPanelWithTable(JTable table, List<ButtonDef> buttons) {
        JPanel panel = new JPanel(new BorderLayout());
        JPanel buttonPanel = new JPanel();
        buttons.forEach(button -> addButton(buttonPanel, button.text(), button.action()));
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
