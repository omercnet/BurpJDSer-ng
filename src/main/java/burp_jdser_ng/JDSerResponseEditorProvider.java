package burp_jdser_ng;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;

class JDSerResponseEditorProvider implements HttpResponseEditorProvider {

    private final MontoyaApi api;
    private final JDSer jdSer;

    JDSerResponseEditorProvider(MontoyaApi api, JDSer jdSer) {
        this.api = api;
        this.jdSer = jdSer;
    }

    @Override
    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext creationContext) {
        return new HttpResponseEditor(api, creationContext, jdSer);
    }

}
