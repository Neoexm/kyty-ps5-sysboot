static void Pump() {
	SDL_Event event;
	while (SDL_PollEvent(&event)) {}
}
