package burp_jdser_ng;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;

class JDSerRequestEditorProvider implements HttpRequestEditorProvider {

    private final MontoyaApi api;
    private final JDSer jdSer;

    JDSerRequestEditorProvider(MontoyaApi api, JDSer jdSer) {
        this.api = api;
        this.jdSer = jdSer;
    }

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext creationContext) {
        return new HttpRequestEditor(api, creationContext, jdSer);
    }

}
