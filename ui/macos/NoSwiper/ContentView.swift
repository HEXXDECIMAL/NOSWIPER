//
//  ContentView.swift
//  NoSwiper
//
//  Main content view (not used - we're a menu bar app).
//

import SwiftUI

struct ContentView: View {
    var body: some View {
        VStack {
            Text("NoSwiper")
                .font(.largeTitle)
                .padding()

            Text("Menu bar app")
                .foregroundColor(.secondary)
        }
        .frame(width: 300, height: 200)
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
